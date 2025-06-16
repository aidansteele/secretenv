package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const Prefix = "ENC@"

func encrypt(ctx context.Context, app, env, key, name, value string) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	api := kms.NewFromConfig(cfg)

	resp, err := api.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     &key,
		Plaintext: []byte(value),
		EncryptionContext: map[string]string{
			"app":  app,
			"env":  env,
			"name": name,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	fmt.Printf("%s%s\n", Prefix, base64.StdEncoding.EncodeToString(resp.CiphertextBlob))
	return nil
}

func decrypt(ctx context.Context, app, env, key, name, value string) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	plaintext, err := decryptValue(ctx, kms.NewFromConfig(cfg), app, env, key, name, value)
	if err != nil {
		return fmt.Errorf("failed to decrypt value: %w", err)
	}

	fmt.Println(plaintext)
	return nil
}

func doExec(ctx context.Context, app, env, key, file string, args []string) error {
	fileContents, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	pairs := map[string]string{}
	err = yaml.Unmarshal(fileContents, &pairs)
	if err != nil {
		return fmt.Errorf("failed to unmarshal YAML (should be string->string map): %w", err)
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	api := kms.NewFromConfig(cfg)
	environ := os.Environ()

	for k, v := range pairs {
		if strings.HasPrefix(v, Prefix) {
			v, err = decryptValue(ctx, api, app, env, key, k, v)
			if err != nil {
				return fmt.Errorf("failed to decrypt value: %w", err)
			}
		}

		environ = append(environ, k+"="+v)
	}

	exe, args := args[0], args[1:]
	path, err := exec.LookPath(exe)
	if err != nil {
		return fmt.Errorf("failed to find executable: %w", err)
	}

	err = syscall.Exec(path, args, environ)
	if err != nil {
		return fmt.Errorf("failed to exec: %w", err)
	}

	return nil
}

func decryptValue(ctx context.Context, api *kms.Client, app, env, key, name, valueB64 string) (string, error) {
	valueB64, ok := strings.CutPrefix(valueB64, Prefix)
	if !ok {
		return "", fmt.Errorf("invalid secret: missing %s prefix", Prefix)
	}

	value, err := base64.StdEncoding.DecodeString(valueB64)
	if err != nil {
		return "", fmt.Errorf("failed to base64 decode: %w", err)
	}

	resp, err := api.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          &key,
		CiphertextBlob: value,
		EncryptionContext: map[string]string{
			"app":  app,
			"env":  env,
			"name": name,
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	plaintext := resp.Plaintext
	return string(plaintext), nil
}

func getFlags(cmd *cobra.Command) (app, env, key string) {
	app, _ = cmd.Root().PersistentFlags().GetString("app")
	if app == "" {
		app = os.Getenv("SECRETENV_APP")
	}

	env, _ = cmd.Root().PersistentFlags().GetString("env")
	if env == "" {
		env = os.Getenv("SECRETENV_ENV")
	}

	key, _ = cmd.Root().PersistentFlags().GetString("key")
	if key == "" {
		key = os.Getenv("SECRETENV_KEY")
	}

	return
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "secretenv",
		Short: "A tool for managing secret environment variables",
		Long:  `secretenv is a CLI tool that helps you manage secret environment variables by providing encryption, decryption, and execution capabilities.`,
	}

	encryptCmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt environment variables",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			app, env, key := getFlags(cmd)
			name, _ := cmd.PersistentFlags().GetString("name")

			fmt.Fprintf(os.Stderr, "Enter plaintext secret: ")
			buf := bufio.NewReader(os.Stdin)
			value, err := buf.ReadString('\n')
			if err != nil {
				return err
			}

			value = strings.TrimSpace(value)
			return encrypt(ctx, app, env, key, name, value)
		},
	}

	decryptCmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt environment variables",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			app, env, key := getFlags(cmd)
			name, _ := cmd.PersistentFlags().GetString("name")

			fmt.Fprintf(os.Stderr, "Enter ciphertext value (including %s prefix): ", Prefix)
			buf := bufio.NewReader(os.Stdin)
			value, err := buf.ReadString('\n')
			if err != nil {
				return err
			}

			value = strings.TrimSpace(value)
			return decrypt(ctx, app, env, key, name, value)
		},
	}

	encryptCmd.PersistentFlags().StringP("name", "n", "", "Environment variable name (e.g. DB_PASSWORD)")
	decryptCmd.PersistentFlags().StringP("name", "n", "", "Environment variable name (e.g. DB_PASSWORD)")

	execCmd := &cobra.Command{
		Use:   "exec",
		Short: "Execute a command with decrypted environment variables",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			app, env, key := getFlags(cmd)

			file, _ := cmd.PersistentFlags().GetString("file")
			if app == "" {
				app = os.Getenv("SECRETENV_FILE")
			}

			return doExec(ctx, app, env, key, file, args)
		},
	}

	execCmd.PersistentFlags().StringP("file", "f", "", "YAML file containing secrets, or env var SECRETENV_FILE")

	rootCmd.PersistentFlags().StringP("app", "a", "", "App name (e.g. hello-world, auth-service), or env var SECRETENV_APP")
	rootCmd.PersistentFlags().StringP("env", "e", "", "Environment name (e.g. dev, prod), or env var SECRETENV_ENV")
	rootCmd.PersistentFlags().StringP("key", "k", "alias/secretenv", "KMS key ID/alias/ARN, or env var SECRETENV_KEY")

	rootCmd.AddCommand(encryptCmd, decryptCmd, execCmd)
	rootCmd.CompletionOptions.HiddenDefaultCmd = true

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
