#ifndef CANTERA_CAS_COLUMNFILE_H_
#define CANTERA_CAS_COLUMNFILE_H_ 1

#include <map>
#include <unordered_set>

#include <columnfile.h>
#include <kj/async.h>

namespace cantera {

class CASClient;

class CASColumnFileOutput : public ColumnFileOutput {
 public:
  CASColumnFileOutput(CASClient* cas_client);

  void Flush(
      const std::vector<std::pair<uint32_t, std::string_view>>& fields,
      const ColumnFileCompression compression) override;

  std::unique_ptr<std::streambuf> Finalize() override;

  // Returns the CAS key of the column file.  This function can only be called
  // after `Finalize()`.
  const std::string& Key() const;

 private:
  typedef std::pair<uint32_t, std::string> Chunk;

  struct Segment {
    std::vector<Chunk> chunks;
    uint32_t compression;
  };

  CASClient* cas_client_;

  std::vector<Segment> segments_;

  std::string key_;
};

class CASColumnFileInput : public ColumnFileInput {
 public:
  CASColumnFileInput(CASClient* cas_client, std::string key);

  bool Next(ColumnFileCompression& compression) override;

  std::vector<std::pair<uint32_t, ColumnFileInput::Buffer>> Fill(
      const std::unordered_set<uint32_t>& field_filter) override;

  bool End() const override;

  void SeekToStart() override;

  size_t Size() const override;

  size_t Offset() const override;

  // Returns the CAS keys associated with the stream.
  std::vector<std::string> Keys() const;

 private:
  typedef std::pair<uint32_t, std::string> Chunk;

  struct Segment {
    std::vector<Chunk> chunks;
    ColumnFileCompression compression;
  };

  std::map<std::pair<uint32_t, uint32_t>,
           kj::Promise<std::pair<uint32_t, ColumnFileInput::Buffer>>>
      chunk_promises_;

  CASClient* cas_client_;
  std::string key_;

  std::vector<Segment> segments_;

  ssize_t segment_index_ = -1;
};

}  // namespace cantera

#endif  // !STORAGE_CA_CAS_COLUMNFILE_H_
