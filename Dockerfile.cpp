FROM debian:bookworm-slim AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ cmake make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY cpp /src/cpp

RUN cmake -S /src/cpp -B /src/cpp/build \
    && cmake --build /src/cpp/build --config Release -j

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /src/cpp/build/ipv11s_openclaw /app/ipv11s_openclaw

CMD ["/app/ipv11s_openclaw"]
