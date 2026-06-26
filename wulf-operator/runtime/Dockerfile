FROM node:22-bookworm-slim

ARG WORKERD_VERSION=1.20260521.1

RUN npm install --global "workerd@${WORKERD_VERSION}" \
  && workerd --version

USER 65532:65532

ENTRYPOINT ["workerd"]
