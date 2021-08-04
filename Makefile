protobuf:
	protoc -I ./encoding/pb --go_out=./encoding/pb ./encoding/pb/records.proto