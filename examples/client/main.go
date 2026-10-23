// This example uses a saved session when present. Credentials are optional
// environment variables and are never printed or embedded in the program.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/AmarnathCJD/AppleDL/music"
)

func run(ctx context.Context) (err error) {
	query := flag.String("query", "", "search term")
	songID := flag.String("song", "", "catalog song ID; otherwise use the first search result")
	destination := flag.String("download", "", "optional NEW directory for ALAC download")
	session := flag.String("session", music.DefaultSessionFile, "portable session file")
	state := flag.String("state", "", "device state directory")
	country := flag.String("country", "", "two-letter catalog country")
	workers := flag.Int("workers", 0, "sample workers: 0 automatic, 1..64 explicit")
	bundle := flag.Bool("export-context", false, "also save encrypted audio and matching private context")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	c, err := music.New(ctx, music.Config{
		Username: os.Getenv("APPLEMUSIC_USERNAME"), Password: os.Getenv("APPLEMUSIC_PASSWORD"),
		SessionFile: *session, StateDir: *state, Country: *country, Workers: *workers, Progress: os.Stdout,
	})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, c.Close()) }()
	id := *songID
	if *query != "" {
		result, err := c.Search(ctx, *query, music.SearchOptions{Limit: 5})
		if err != nil {
			return err
		}
		for _, song := range result.Songs {
			fmt.Printf("%s: %s — %s\n", song.ID, song.Name, song.Artist)
		}
		if id == "" && len(result.Songs) > 0 {
			id = result.Songs[0].ID
		}
	}
	if id != "" {
		song, err := c.GetSong(ctx, id)
		if err != nil {
			return err
		}
		fmt.Printf("Song: %s — %s; formats=%d\n", song.Name, song.Artist, len(song.Formats))
		for _, format := range song.Formats {
			fmt.Printf("  %s: %s, %d bits/s, download=%t\n", format.ID, format.Codec, format.Bandwidth, format.DownloadSupported)
		}
	}
	if *destination != "" {
		if id == "" {
			return errors.New("download requires -song or a successful -query")
		}
		r, err := c.DownloadAndDecryptSong(ctx, id, *destination, music.DownloadOptions{ExportContext: *bundle})
		if err != nil {
			return err
		}
		fmt.Printf("Downloaded %s: %d Hz, %d-bit, %d channels\n", r.Path, r.SampleRate, r.BitDepth, r.Channels)
		fmt.Printf("Workers=%d, samples=%d, sample pass=%s, decryption=%s, total=%s\n", r.Workers, r.Samples, r.SampleDuration, r.DecryptionDuration, r.TotalDuration)
	}
	if err := c.SaveSession(""); err != nil {
		return err
	}
	fmt.Println("Portable session saved; reuse the same session file on the next run.")
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Apple Music:", err)
		os.Exit(1)
	}
}
