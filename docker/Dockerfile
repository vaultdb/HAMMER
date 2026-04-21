# VaultDB HAMMER Docker image
#
# Requires base image: dhsohn/vaultdb-fhe:latest (see Dockerfile.base)
# Build from repo root: docker build -t vaultdb:latest -f src/main/cpp/docker/Dockerfile .

FROM dhsohn/vaultdb-fhe:latest

# ---------- Build VaultDB ----------
COPY . /build/vaultdb
WORKDIR /build/vaultdb/src/main/cpp
RUN cmake -DCMAKE_BUILD_TYPE=Release . && make -j$(nproc)

# ---------- Install to /opt/vaultdb ----------
RUN mkdir -p /opt/vaultdb/lib /opt/vaultdb/bin /opt/vaultdb/scripts /opt/vaultdb/test \
    && cp libvaultdb-emp.so /opt/vaultdb/lib/ \
    && cp bin/* /opt/vaultdb/bin/ \
    && cp -r conf/ /opt/vaultdb/conf/ \
    && cp -r profiles/ /opt/vaultdb/profiles/ \
    && cp -r scripts/HAMMER/ /opt/vaultdb/scripts/HAMMER/ \
    && cp -r test/support/ /opt/vaultdb/test/support/ \
    && cp docker/entrypoint.sh /opt/vaultdb/ \
    && chmod +x /opt/vaultdb/entrypoint.sh \
    && rm -rf /build/vaultdb

ENV LD_LIBRARY_PATH=/opt/vaultdb/lib:/usr/local/lib
WORKDIR /opt/vaultdb
ENTRYPOINT ["/opt/vaultdb/entrypoint.sh"]
