FROM liuchong/rustup:musl
WORKDIR /opt/gtrace
ADD . /opt/gtrace
RUN cargo build --target x86_64-unknown-linux-musl --release
ENTRYPOINT [ "/opt/gtrace/target/x86_64-unknown-linux-musl/release" ]
    