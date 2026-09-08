# chinadns-ng 容器镜像
# 构建:
#   docker build -t chinadns-ng .
# 运行 (ipset 需要 CAP_NET_ADMIN, 容器 53 端口映射到本机 53):
#   docker run -d --name chinadns-ng --cap-add NET_ADMIN \
#     -p 53:53/tcp -p 53:53/udp chinadns-ng
# 注意: 宿主机需支持 ipset, 内核模块 ip_set/ip_set_hash_net/ip_set_hash_net6
#       需已加载 (通常会自动加载).
FROM alpine:3.24

RUN apk add --no-cache ipset

# 静态链接的 musl 二进制, 重命名为 chinadns-ng
COPY zig-out/bin/chinadns-ng@x86_64-linux-musl@x86_64_v3@fast+lto /usr/local/bin/chinadns-ng

# 域名列表与 ipset 规则文件
COPY res/ /etc/chinadns/
COPY chinadns.conf /etc/chinadns/chinadns.conf

WORKDIR /etc/chinadns

EXPOSE 53/tcp 53/udp

# 启动时先恢复 ipset 规则, 再运行 chinadns-ng
CMD cd /etc/chinadns && \
    ipset -R -exist < chnroute.ipset && \
    ipset -R -exist < chnroute6.ipset && \
    exec chinadns-ng -C chinadns.conf