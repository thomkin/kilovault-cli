package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/thomkin/kilovault-cli/pkg/client"
	"github.com/urfave/cli/v2"
)

// resolveBatchSecret resolves the secret that decrypts/encrypts the
// batch FILE itself. This is a distinct secret from -s/--secret, which
// encrypts/decrypts individual VALUES inside it (client.ResolveSecret).
//
// Priority: flag > KILOVAULT_BATCH_SECRET env var. Deliberately no
// config-file fallback, unlike ResolveSecret — the whole point of a
// batch file is to keep this secret off disk and out of shell history;
// writing it to ~/.config/kilovault/config.json would undermine that.
func resolveBatchSecret(flagSecret string) (string, error) {
	if flagSecret != "" {
		return flagSecret, nil
	}
	if envSecret := os.Getenv("KILOVAULT_BATCH_SECRET"); envSecret != "" {
		return envSecret, nil
	}
	return "", fmt.Errorf("batch file secret required: use --batch-secret or set KILOVAULT_BATCH_SECRET")
}

func runBatchRun(c *cli.Context) error {
	path := c.String("file")
	if path == "" {
		return fmt.Errorf("file required: use -f/--file")
	}
	if c.NArg() > 0 {
		return fmt.Errorf("unexpected argument(s): %v (use -f/--file to specify the batch file)", c.Args().Slice())
	}

	batchSecret, err := resolveBatchSecret(c.String("batch-secret"))
	if err != nil {
		return err
	}

	encrypted, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read batch file %q: %v", path, err)
	}
	if !client.IsEncrypted(string(encrypted)) {
		return fmt.Errorf("batch file %q is not encrypted (expected the output of `kilovault batch encrypt`)", path)
	}

	plaintext, err := client.DecryptBytes(batchSecret, string(encrypted))
	if err != nil {
		return fmt.Errorf("failed to decrypt batch file: wrong --batch-secret/KILOVAULT_BATCH_SECRET or corrupted file")
	}
	defer client.ZeroBytes(plaintext)

	ops, err := client.ParseBatch(plaintext)
	if err != nil {
		return err
	}

	valueSecret := client.ResolveSecret(c.String("secret"))
	cl := client.NewWithToken(getEndpoint(c), c.String("token"))

	for i, op := range ops {
		label := fmt.Sprintf("[%d/%d] %s %s", i+1, len(ops), op.Op, op.Key)
		if err := execBatchOp(cl, valueSecret, op); err != nil {
			fmt.Printf("✗ %s: %v\n", label, err)
			return fmt.Errorf("batch stopped after %d/%d op(s) — earlier ops already applied are NOT rolled back", i, len(ops))
		}
		fmt.Printf("✓ %s\n", label)
	}

	fmt.Printf("✓ Batch complete: %d op(s)\n", len(ops))
	return nil
}

func execBatchOp(cl *client.Client, secret string, op client.BatchOp) error {
	switch op.Op {
	case "set":
		value := *op.Value
		if !op.Raw {
			var err error
			value, err = encryptIfSecret(value, secret)
			if err != nil {
				return err
			}
		}
		if op.User != "" {
			return cl.VaultAdminSet(op.User, op.Key, value)
		}
		return cl.VaultSet(op.Key, value)

	case "attr":
		result, err := cl.VaultGet(op.Key)
		if err != nil {
			return fmt.Errorf("request failed: %v", err)
		}

		var doc interface{}
		if result.Value == "" {
			doc = map[string]interface{}{}
		} else {
			plain, err := decryptIfNeeded(result.Value, secret)
			if err != nil {
				return err
			}
			if err := json.Unmarshal([]byte(plain), &doc); err != nil {
				return fmt.Errorf("value at %q is not valid JSON: %v", op.Key, err)
			}
		}

		for _, path := range op.Remove {
			doc, err = client.RemoveAttrPath(doc, client.ParseAttrPath(path))
			if err != nil {
				return fmt.Errorf("remove %q: %v", path, err)
			}
		}
		for _, e := range op.Set {
			doc, err = client.SetAttrPath(doc, client.ParseAttrPath(e.Path), e.Value)
			if err != nil {
				return fmt.Errorf("set %q: %v", e.Path, err)
			}
		}

		encoded, err := json.Marshal(doc)
		if err != nil {
			return fmt.Errorf("failed to encode result: %v", err)
		}
		newValue, err := encryptIfSecret(string(encoded), secret)
		if err != nil {
			return err
		}
		return cl.VaultSet(op.Key, newValue)

	case "delete":
		_, err := cl.VaultAdminDelete(op.User, op.Key)
		if err != nil {
			return fmt.Errorf("request failed: %v", err)
		}
		return nil

	default:
		return fmt.Errorf("unknown op %q", op.Op)
	}
}

// runBatchExport dumps every currently-stored vault key (optionally
// scoped to one user) into a fresh encrypted batch file, as "set" ops
// with Raw=true so each value round-trips through `batch run` exactly
// as stored on the server — whether that's plaintext or already
// client-side ciphertext. Values never touch disk unencrypted: they're
// assembled in memory and the JSON is encrypted before the first write.
func runBatchExport(c *cli.Context) error {
	outPath := c.String("out")
	if outPath == "" {
		return fmt.Errorf("output file required: use -o/--out")
	}
	if c.NArg() > 0 {
		return fmt.Errorf("unexpected argument(s): %v (use -o/--out to specify the output file)", c.Args().Slice())
	}

	batchSecret, err := resolveBatchSecret(c.String("batch-secret"))
	if err != nil {
		return err
	}

	var userID *string
	if u := c.String("user"); u != "" {
		userID = &u
	}

	cl := client.NewWithToken(getEndpoint(c), c.String("token"))

	listResult, err := cl.VaultAdminList(userID)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	if len(listResult.Keys) == 0 {
		return fmt.Errorf("no keys found to export")
	}

	ops := make([]client.BatchOp, 0, len(listResult.Keys))
	for _, k := range listResult.Keys {
		got, err := cl.VaultAdminGet(k.UserID, k.Key)
		if err != nil {
			return fmt.Errorf("failed to fetch %s/%s: %v", k.UserID, k.Key, err)
		}
		value := got.Value
		ops = append(ops, client.BatchOp{
			Op:    "set",
			Key:   k.Key,
			User:  k.UserID,
			Value: &value,
			Raw:   true,
		})
	}

	encoded, err := json.Marshal(ops)
	if err != nil {
		return fmt.Errorf("failed to encode backup: %v", err)
	}
	defer client.ZeroBytes(encoded)

	encrypted, err := client.Encrypt(batchSecret, string(encoded))
	if err != nil {
		return fmt.Errorf("failed to encrypt backup: %v", err)
	}

	if err := os.WriteFile(outPath, []byte(encrypted), 0600); err != nil {
		return fmt.Errorf("failed to write %q: %v", outPath, err)
	}

	fmt.Printf("✓ Exported %d key(s) to %s\n", len(ops), outPath)
	fmt.Fprintln(os.Stderr, "  Restore with: kilovault batch run -f <this file> -t <admin-token>")
	return nil
}

func runBatchEncrypt(c *cli.Context) error {
	inPath := c.String("in")
	if inPath == "" {
		return fmt.Errorf("input file required: use -i/--in (a plaintext JSON batch file)")
	}
	outPath := c.String("out")
	if outPath == "" {
		return fmt.Errorf("output file required: use -o/--out")
	}

	batchSecret, err := resolveBatchSecret(c.String("batch-secret"))
	if err != nil {
		return err
	}

	plaintext, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("failed to read %q: %v", inPath, err)
	}

	if _, err := client.ParseBatch(plaintext); err != nil {
		return fmt.Errorf("%q is not a valid batch file: %v", inPath, err)
	}

	encrypted, err := client.Encrypt(batchSecret, string(plaintext))
	if err != nil {
		return fmt.Errorf("failed to encrypt: %v", err)
	}

	if err := os.WriteFile(outPath, []byte(encrypted), 0600); err != nil {
		return fmt.Errorf("failed to write %q: %v", outPath, err)
	}

	fmt.Printf("✓ Wrote encrypted batch file to %s\n", outPath)
	fmt.Fprintf(os.Stderr, "  Remember to securely delete the plaintext input file %q — it still holds all the secrets in the clear.\n", inPath)
	return nil
}

func runBatchDecrypt(c *cli.Context) error {
	path := c.String("file")
	if path == "" {
		return fmt.Errorf("file required: use -f/--file")
	}

	batchSecret, err := resolveBatchSecret(c.String("batch-secret"))
	if err != nil {
		return err
	}

	encrypted, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read batch file %q: %v", path, err)
	}

	plaintext, err := client.DecryptBytes(batchSecret, string(encrypted))
	if err != nil {
		return fmt.Errorf("failed to decrypt batch file: wrong --batch-secret/KILOVAULT_BATCH_SECRET or corrupted file")
	}
	defer client.ZeroBytes(plaintext)

	if outPath := c.String("out"); outPath != "" {
		if err := os.WriteFile(outPath, plaintext, 0600); err != nil {
			return fmt.Errorf("failed to write %q: %v", outPath, err)
		}
		fmt.Fprintf(os.Stderr, "✓ Wrote decrypted batch to %s (mode 0600) — it holds plaintext secrets, delete it when done.\n", outPath)
		return nil
	}

	fmt.Fprintln(os.Stderr, "WARNING: printing decrypted batch contents to stdout — this is plaintext, including secrets.")
	fmt.Println(string(plaintext))
	return nil
}
