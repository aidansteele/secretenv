# secretenv

```yaml
# my-secrets.yml
# secretenv installation
#   macos: brew install --cask aidansteele/taps/secretenv
#   docker:
#     FROM ghcr.io/aidansteele/secretenv:latest AS secretenv
#     COPY --from=secretenv /ko-app/secretenv /usr/bin/secretenv
#     ENV SECRETENV_APP=my-app 
#     ENV SECRETENV_ENV=production 
#     ENV SECRETENV_FILE=/my-secrets.yml
#     ENV SECRETENV_KEY=alias/secretenv # optional, this is the default
#     ENTRYPOINT ["/usr/bin/secretenv", "exec", "--"]
#     COPY my-secrets.yml /
#     CMD ["/my-app"]
# usage
#   secretenv encrypt -a my-app -e production -k alias/secretenv -n DB_PASSWORD
#   # enter in your secret value. copy and paste the encrypted value to this yaml file.
#   secretenv decrypt -a my-app -e production -k alias/secretenv -n DB_PASSWORD
#   # paste in your secret value. see the decrypted value

# plaintext values are passed through as-is
HELLO_WORLD: this is a plaintext value
# encrypted values are decrypted by the `exec` subcommand before executing your app
DB_PASSWORD: ENC@AQICAHjJTRAubNuiTN9YepVYoKIjhjkx/AVNLVqLk8kpn1jc9wFsXHlpWMQTkHWDpBOBel71AAAAYzBhBgkqhkiG9w0BBwagVDBSAgEAME0GCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMphj7hqQiJT7OhT2SAgEQgCAdvgWluEqYGJIJi8EIOCZUGPMVjxqjWN8zz4T3KTWB5Q==
```
