# 런타임 의존성 0(표준 라이브러리만)이라 alpine 베이스로 최소 이미지 구성
FROM python:3.12-alpine

WORKDIR /build
COPY pyproject.toml README.md ./
COPY vibeguard ./vibeguard
RUN pip install --no-cache-dir .

# 스캔 대상은 /scan에 읽기 전용 마운트해서 사용
RUN adduser -D scanner
USER scanner
WORKDIR /scan

ENTRYPOINT ["vibeguard"]
CMD ["--help"]
