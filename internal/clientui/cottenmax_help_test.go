package clientui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"cottendns-go/internal/client"
	"cottendns-go/internal/config"
	"cottendns-go/internal/tunnelinfo"
)

func TestDashboardShowsSelectedModeAcrossTerminalSizes(t *testing.T) {
	for _, mode := range []string{config.TunnelLegacy, config.TunnelCottenMax} {
		for _, width := range []int{40, 80, 120} {
			m := model{width: width, height: 32, started: time.Now(), status: client.StatusSnapshot{TunnelMode: mode, Phase: "connecting", Transport: "udp"}}
			view := ansi.Strip(m.View())
			if !strings.Contains(view, tunnelinfo.ModeLabel(mode)) {
				t.Fatalf("width %d: selected mode missing: %s", width, view)
			}
			if !strings.Contains(view, "h / ?") {
				t.Fatalf("width %d: help entry missing", width)
			}
		}
	}
}

func TestSetupHelpFitsAndScrollsWithoutStoppingClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, width := range []int{20, 40, 80, 120} {
		m := model{width: width, height: 12, ctx: ctx, cancel: cancel,
			status:   client.StatusSnapshot{TunnelMode: config.TunnelCottenMax},
			guidance: tunnelinfo.Client(config.ClientConfig{TunnelMode: config.TunnelCottenMax, ResolverTransport: "auto"}),
		}
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
		m = updated.(model)
		if !m.showHelp {
			t.Fatal("h did not open setup help")
		}
		first := m.View()
		last := first
		for i := 0; i < 30; i++ {
			updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
			m = updated.(model)
			view := m.View()
			if len(strings.Split(view, "\n")) > m.height {
				t.Fatalf("width %d: too many rows", width)
			}
			for _, line := range strings.Split(view, "\n") {
				if ansi.StringWidth(line) > width {
					t.Fatalf("width %d overflow: %q", width, line)
				}
			}
			last = view
		}
		if first == last {
			t.Fatalf("width %d: help did not scroll", width)
		}
		updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
		m = updated.(model)
		if m.showHelp || m.stopping || ctx.Err() != nil {
			t.Fatal("Esc in help should return without stopping the running client")
		}
	}
}
