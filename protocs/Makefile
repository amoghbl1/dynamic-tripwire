PROTO_DIR = .

protobuf: clean
	protoc -I=${PROTO_DIR} --python_out=${PROTO_DIR}  ${PROTO_DIR}/messages.proto
	protoc --js_out=import_style=commonjs,binary:. ${PROTO_DIR}/messages.proto

clean:
	rm -rf ${PROTO_DIR}/*.pyc
	rm -rf ${PROTO_DIR}/*_pb2.py
	rm -rf ${PROTO_DIR}/*_pb.js
