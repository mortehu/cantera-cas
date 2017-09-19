// Copyright 2013, 2014, 2015, 2016 Morten Hustveit <morten.hustveit@gmail.com>
// Copyright 2013, 2014, 2015, 2016 eVenture Capital Partners
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cas-columnfile.h"

#include <algorithm>
#include <memory>

#include <capnp/message.h>
#include <capnp/serialize.h>

#include "client.h"
#include "proto/columnfile.capnp.h"

namespace cantera {

CASColumnFileOutput::CASColumnFileOutput(CASClient* cas_client)
    : cas_client_(cas_client) {}

void CASColumnFileOutput::Flush(
    const std::vector<std::pair<uint32_t, std::string_view>>& chunks,
    const cantera::ColumnFileCompression compression) {
  KJ_REQUIRE(key_.empty());

  auto key_promises =
      kj::heapArrayBuilder<kj::Promise<std::pair<uint32_t, std::string>>>(
          chunks.size());

  for (const auto& chunk : chunks) {
    key_promises.add(
        cas_client_->PutAsync(chunk.second.data(), chunk.second.size())
            .then([column = chunk.first](auto key) {
              return std::make_pair(column, std::move(key));
            }));
  }

  // TODO(mortehu): We don't actually need to block until `Finalize()` is
  // called.
  auto keys =
      kj::joinPromises(key_promises.finish()).wait(cas_client_->WaitScope());

  segments_.emplace_back();

  Segment& new_segment = segments_.back();

  for (auto& key : keys) new_segment.chunks.emplace_back(std::move(key));
  new_segment.compression = static_cast<uint32_t>(compression);
}

std::unique_ptr<std::streambuf> CASColumnFileOutput::Finalize() {
  KJ_REQUIRE(key_.empty());

  capnp::MallocMessageBuilder message;

  auto index = message.initRoot<CASColumnFileIndex>();

  auto segments = index.initSegments(segments_.size());

  for (size_t segment_index = 0; segment_index < segments_.size();
       ++segment_index) {
    const auto& input_segment = segments_[segment_index];
    auto output_segment = segments[segment_index];

    auto chunks = output_segment.initChunks(input_segment.chunks.size());

    for (size_t chunk_index = 0; chunk_index < input_segment.chunks.size();
         ++chunk_index) {
      auto output_chunk = chunks[chunk_index];
      output_chunk.setColumn(input_segment.chunks[chunk_index].first);
      output_chunk.setCasKey(input_segment.chunks[chunk_index].second);
    }

    output_segment.setCompression(input_segment.compression);
  }

  const auto message_data = capnp::messageToFlatArray(message);
  const auto message_bytes = message_data.asBytes();

  key_ = cas_client_->Put(message_bytes.begin(), message_bytes.size());

  return nullptr;
}

const std::string& CASColumnFileOutput::Key() const {
  KJ_REQUIRE(!key_.empty());
  return key_;
}

CASColumnFileInput::CASColumnFileInput(CASClient* cas_client, std::string key)
    : cas_client_(cas_client), key_(std::move(key)) {
  auto message_data = cas_client_->Get(key_);

  capnp::FlatArrayMessageReader message(
      kj::arrayPtr(reinterpret_cast<const capnp::word*>(message_data.begin()),
                   message_data.size() / sizeof(capnp::word)));

  auto index = message.getRoot<CASColumnFileIndex>();
  auto input_segments = index.getSegments();

  segments_.resize(input_segments.size());

  for (size_t segment_index = 0; segment_index < segments_.size();
       ++segment_index) {
    auto& output_segment = segments_[segment_index];
    auto input_segment = input_segments[segment_index];
    auto input_chunks = input_segment.getChunks();

    output_segment.compression = static_cast<cantera::ColumnFileCompression>(
        input_segment.getCompression());
    output_segment.chunks.resize(input_chunks.size());

    for (size_t chunk_index = 0; chunk_index < output_segment.chunks.size();
         ++chunk_index) {
      auto input_chunk = input_chunks[chunk_index];
      auto& output_chunk = output_segment.chunks[chunk_index];

      KJ_REQUIRE(input_chunk.hasCasKey());

      output_chunk.first = input_chunk.getColumn();
      output_chunk.second = input_chunk.getCasKey();
    }
  }
}

bool CASColumnFileInput::Next(cantera::ColumnFileCompression& compression) {
  segment_index_ =
      std::min(static_cast<size_t>(segment_index_) + 1, segments_.size());

  if (static_cast<size_t>(segment_index_) == segments_.size()) return false;

  compression = segments_[segment_index_].compression;

  return true;
}

std::vector<std::pair<uint32_t, cantera::ColumnFileInput::Buffer>>
CASColumnFileInput::Fill(const std::unordered_set<uint32_t>& field_filter) {
  KJ_REQUIRE(segment_index_ >= 0 &&
                 static_cast<size_t>(segment_index_) < segments_.size(),
             segment_index_, segments_.size());

  const auto& segment = segments_[segment_index_];

  size_t matching_columns = 0;
  if (field_filter.empty()) {
    matching_columns = segment.chunks.size();
  } else {
    for (const auto& chunk : segment.chunks) {
      if (field_filter.count(chunk.first)) ++matching_columns;
    }
  }

  // This constant needs to be at least 1.
  static const size_t kPrefetchLength = 2;

  // Discard requests that are outside our current range.
  for (auto i = chunk_promises_.begin(); i != chunk_promises_.end();) {
    if (i->first.second < segment_index_ ||
        i->first.second >= segment_index_ + kPrefetchLength) {
      i = chunk_promises_.erase(i);
    } else {
      ++i;
    }
  }

  auto row_promises = kj::heapArrayBuilder<
      kj::Promise<std::pair<uint32_t, cantera::ColumnFileInput::Buffer>>>(
      matching_columns);

  for (size_t offset = 0; offset < kPrefetchLength; ++offset) {
    if (segment_index_ + offset >= segments_.size()) continue;

    const auto& fetch_segment = segments_[segment_index_ + offset];

    for (const auto& chunk : fetch_segment.chunks) {
      if (!field_filter.empty() && !field_filter.count(chunk.first)) continue;

      const auto key = std::make_pair(chunk.first, segment_index_ + offset);

      auto i = chunk_promises_.find(key);
      if (i != chunk_promises_.end()) {
        if (!offset) {
          row_promises.add(std::move(i->second));
          chunk_promises_.erase(i);
        }
        continue;
      }

      auto data_promise = cas_client_->GetAsync(chunk.second)
                              .then([column = chunk.first](auto data) {
                                  Buffer result{data.size()};
                                  std::memcpy(result.data(), data.begin(), result.size());
                                return std::make_pair(column, std::move(result));
                              })
                              .eagerlyEvaluate(nullptr);

      if (!offset) {
        row_promises.add(std::move(data_promise));
      } else {
        chunk_promises_.emplace(key, std::move(data_promise));
      }
    }
  }

  auto chunks =
      kj::joinPromises(row_promises.finish()).wait(cas_client_->WaitScope());

  std::vector<std::pair<uint32_t, Buffer>> result;

  for (auto& chunk : chunks) result.emplace_back(std::move(chunk));

  return result;
}

bool CASColumnFileInput::End() const {
  return static_cast<size_t>(segment_index_) == segments_.size();
}

void CASColumnFileInput::SeekToStart() { segment_index_ = 0; }

size_t CASColumnFileInput::Size() const { return segments_.size(); }

size_t CASColumnFileInput::Offset() const {
  return std::min(segments_.size(), static_cast<size_t>(segment_index_ + 1));
}

std::vector<std::string> CASColumnFileInput::Keys() const {
  std::vector<std::string> result;

  for (const auto& segment : segments_) {
    for (const auto& chunk : segment.chunks) result.emplace_back(chunk.second);
  }

  result.emplace_back(key_);

  return result;
}

}  // namespace cantera
