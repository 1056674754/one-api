#### 需要配置以下参数:
VUE_APP_TOP_LEVEL_DOMAIN=example.com


#### 编译:
go build -ldflags "-s -w" -o one-api
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o one-api2
rsync one-api2 SUIS-QP-TX-LIGHT-USA-1:/root/DockerOneAPI

#### 测试启动:
./one-api --port 3000 --log-dir ./logs
