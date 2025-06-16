# secretenv

```yaml
# my-secrets.yml
# secretenv installation
#   macos: see instructions below
#   docker: see example dockerfile below
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

## macOS usage

If you have Go installed, you can do the following:

1. `go install github.com/aidansteele/secretenv@latest`
2. `~/go/bin/secretenv`

If you don't, run the following instructions. NOTE: Instructions 2-6 will 
become unnecessary once I have code-signing set up.

1. Install using Homebrew: `brew install --cask aidansteele/taps/secretenv`
2. Run `secretenv`. It will fail. Click "Done"
3. Open Settings app
4. Select "Privacy and Security tab" and scroll to the bottom.
5. Look for "secretenv was blocked to protect your Mac." Click "Allow anyway"
6. Try run `secretenv` again. Click "Open Anyway"

## Docker usage

```dockerfile
FROM ghcr.io/aidansteele/secretenv:latest AS secretenv
COPY --from=secretenv /ko-app/secretenv /usr/bin/secretenv
ENV SECRETENV_APP=my-app 
ENV SECRETENV_ENV=production 
ENV SECRETENV_FILE=/my-secrets.yml
ENV SECRETENV_KEY=alias/secretenv
ENTRYPOINT ["/usr/bin/secretenv", "exec", "--"]
COPY my-secrets.yml /
CMD ["/my-app"]
```
