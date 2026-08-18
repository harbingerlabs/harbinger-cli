package report

import (
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/harbingerlabs/harbinger-cli/internal/analyze"
)

// HTML writes a self-contained, shareable report.
//
// DESIGN CONTRACT — this file is the product from the buyer's side.
//
//   - Zero external requests. No fonts, images, scripts, or stylesheets are
//     fetched. A security buyer must be able to open it on an air-gapped host
//     and a reviewer must be able to confirm it phones nobody.
//   - Two readers, one document. The top half answers "is this bad and what do
//     we do about it" for a service-delivery manager. Below an explicit seam,
//     the ranked paths stay precise for the engineer making the change. The
//     seam is labelled rather than implied, because pretending one register
//     serves both readers is what makes security reports go unread.
//   - Typographic rule: anything the tool measured is set in mono; anything a
//     human would say out loud is set in sans. Identifiers, SIDs, risk figures
//     and edge names are machine facts and look like it.
//   - It must print. MSPs PDF this for clients, so there is a real light-mode
//     print stylesheet; severity survives as rule weight and label, never as a
//     background fill the browser will drop.
func HTML(w io.Writer, r *analyze.Result, top int) error {
	data := struct {
		R         *analyze.Result
		Top       int
		Blind     int
		Quiet     int
		S         Summary
		Fix       string
		Generated string
	}{R: r, Top: top, S: Summarize(r), Generated: time.Now().UTC().Format("2 January 2006, 15:04 MST")}
	if r.TopFix != nil {
		data.Fix = Remediation(r.TopFix.Edge, r.TopFix.Label, r.TopFix.FromName, r.TopFix.ToName)
	}
	for _, p := range r.Paths {
		if p.BlindSpot {
			data.Blind++
		}
		for _, s := range p.Steps {
			if s.Detect < quietThreshold {
				data.Quiet++
			}
		}
	}
	return htmlTmpl.Execute(w, data)
}

// quietThreshold is the detection probability below which a step is treated as
// one routine monitoring would probably not surface.
const quietThreshold = 0.3

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"pct":  fmtPct,
	"risk": fmtRisk,
	"limit": func(top int, ps []analyze.ScoredPath) []analyze.ScoredPath {
		if len(ps) > top {
			return ps[:top]
		}
		return ps
	},
	"quiet":     func(s analyze.Step) bool { return s.Detect < quietThreshold },
	"quietHops": quietHops,
	"verdictWord": func(v string) string {
		switch v {
		case "exposed":
			return "Exposed"
		case "watch":
			return "Watched"
		case "incomplete":
			return "Incomplete"
		default:
			return "Clear"
		}
	},
	"lower": strings.ToLower,
	"sub":   func(a, b int) int { return a - b },
}).Parse(htmlSource))

func quietHops(p analyze.ScoredPath) int {
	n := 0
	for _, s := range p.Steps {
		if s.Detect < quietThreshold {
			n++
		}
	}
	return n
}

const htmlSource = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack-path exposure — {{.R.CrownName}}</title>
<style>
/* ── palette ───────────────────────────────────────────────────────────────
   A control-room palette rather than a dashboard one: the ground is a cold
   slate-blue rather than neutral black, and colour is semantic throughout.
   ember = a route that would go unseen · signal = a route monitoring covers
   amber = we could not see · violet = the tool itself, used sparingly       */
:root{
  --ground:#0a0f18; --raise:#111826; --sunk:#080c14;
  --rule:#1e2838; --rule-soft:#161f2d;
  --ink:#e8ecf4; --ink-soft:#9aa6bd; --ink-faint:#5f6d85;
  --ember:#ff6b4a; --ember-dim:#3a1a14;
  --signal:#3ddca0; --signal-dim:#0e2c22;
  --amber:#f5b544; --amber-dim:#33260e;
  --violet:#8b6cff;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--ground);color:var(--ink);
  font:16px/1.6 var(--sans);font-feature-settings:"kern","liga";
  -webkit-font-smoothing:antialiased}
.wrap{max-width:920px;margin:0 auto;padding:clamp(28px,5vw,64px) clamp(20px,4vw,40px) 96px}

/* ── masthead ─────────────────────────────────────────────────────────── */
.mast{display:flex;justify-content:space-between;align-items:baseline;gap:16px;
  flex-wrap:wrap;padding-bottom:14px;border-bottom:1px solid var(--rule)}
.wordmark{font:600 13px/1 var(--sans);letter-spacing:.22em;text-transform:uppercase;
  color:var(--ink-soft)}
.wordmark b{color:var(--violet);font-weight:600}
.mast .when{font:400 12px/1 var(--mono);color:var(--ink-faint)}

/* ── verdict ──────────────────────────────────────────────────────────────
   The one thing a manager reads. Status word, then the finding as a sentence.
   Type is the emphasis; there is no coloured slab to lose when printed.     */
.verdict{padding:36px 0 4px}
.status{display:inline-flex;align-items:center;gap:10px;
  font:600 12px/1 var(--mono);letter-spacing:.18em;text-transform:uppercase;
  padding:7px 12px;border-radius:2px;border:1px solid currentColor}
.status .dot{width:7px;height:7px;border-radius:50%;background:currentColor}
.v-exposed .status{color:var(--ember)}
.v-watch  .status{color:var(--signal)}
.v-clear  .status{color:var(--signal)}
.v-incomplete .status{color:var(--amber)}
.finding{font:650 clamp(26px,4.2vw,40px)/1.18 var(--sans);letter-spacing:-.022em;
  margin:20px 0 0;max-width:20ch;text-wrap:balance}
.v-exposed .finding{max-width:24ch}

/* ── prose blocks ─────────────────────────────────────────────────────── */
.block{margin-top:40px}
.eyebrow{font:600 11px/1 var(--mono);letter-spacing:.2em;text-transform:uppercase;
  color:var(--ink-faint);margin-bottom:12px}
.prose{font-size:17px;line-height:1.65;color:var(--ink-soft);max-width:64ch;margin:0}
.prose strong{color:var(--ink);font-weight:600}

/* The action is the sentence someone acts on, so it is set at reading size
   for a person, not shrunk into a callout. */
.action{border-left:2px solid var(--signal);padding:2px 0 2px 20px;max-width:64ch}
.action p{margin:0;font-size:18px;line-height:1.55;color:var(--ink);font-weight:520}
.action .caveat{margin-top:10px;font-size:14px;color:var(--ink-soft);font-weight:400}

.facts{list-style:none;margin:0;padding:0;max-width:64ch}
.facts li{position:relative;padding-left:20px;margin:9px 0;color:var(--ink-soft);
  font-size:15px;line-height:1.55}
.facts li::before{content:"";position:absolute;left:2px;top:.65em;
  width:6px;height:1px;background:var(--ink-faint)}
.gaps{border-left:2px solid var(--amber);padding-left:20px;max-width:64ch}
.gaps .lede{margin:0 0 10px;font-size:15px;color:var(--ink)}
.gaps .facts li::before{background:var(--amber)}

/* ── the seam ─────────────────────────────────────────────────────────────
   An explicit change of reader. Naming it is more honest than a rule and a
   change of density, which is what most reports do and nobody notices.     */
.seam{display:flex;align-items:center;gap:18px;margin:64px 0 8px}
.seam::before,.seam::after{content:"";height:1px;background:var(--rule);flex:1}
.seam span{font:600 11px/1 var(--mono);letter-spacing:.16em;text-transform:uppercase;
  color:var(--ink-faint);white-space:nowrap}

/* ── ranked routes ────────────────────────────────────────────────────── */
.route{border:1px solid var(--rule);border-radius:4px;background:var(--raise);
  padding:18px 20px;margin:14px 0}
.route.blind{border-left:2px solid var(--ember)}
.route .shared{margin:12px 0 0;font:400 13px/1.5 var(--sans);color:var(--ink-faint)}
.route.seen{border-left:2px solid var(--signal)}
.route-head{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;
  font:400 13px/1.4 var(--mono);color:var(--ink-soft)}
.rank{font-weight:700;font-size:15px;color:var(--ink)}
.route-head .sep{color:var(--rule)}
.route-head b{color:var(--ink);font-weight:600}
.tag{font:600 11px/1 var(--mono);letter-spacing:.09em;text-transform:uppercase;
  padding:4px 8px;border-radius:2px;border:1px solid currentColor}
.tag.blind{color:var(--ember)}
.tag.seen{color:var(--signal)}
.tag.crown{color:var(--amber)}

/* ── the chain: this report's signature ───────────────────────────────────
   Each hop shows whether monitoring would notice that step. A dashed, dimmed
   connector is a quiet hop — the thing the product exists to find. Reading
   the chain tells you *where* along the route you would lose sight of it,
   which a single risk number cannot.                                       */
/* Chains wrap rather than scroll. A long path clipped at the right edge reads
   as a broken report, and a horizontal scrollbar is lost entirely in print. */
.chain{margin-top:14px}
.chain-inner{display:flex;flex-wrap:wrap;align-items:center;row-gap:10px}
.hop{display:flex;align-items:center}
.who{font:500 13px/1.3 var(--mono);color:var(--ink);background:var(--sunk);
  border:1px solid var(--rule);border-radius:3px;padding:7px 11px;white-space:nowrap}
.who.crown{border-color:var(--amber);color:var(--amber)}
.step{display:flex;flex-direction:column;align-items:center;justify-content:center;
  padding:0 4px;min-width:116px}
.step .what{font:500 11px/1 var(--mono);letter-spacing:.04em;white-space:nowrap;
  padding-bottom:5px}
.step .line{width:100%;height:0;border-top:1px solid var(--ink-faint)}
.step .note{font:400 10px/1 var(--mono);letter-spacing:.06em;text-transform:uppercase;
  padding-top:5px;color:var(--ink-faint)}
.step.loud .what{color:var(--ink-soft)}
.step.hush .what{color:var(--ember)}
.step.hush .line{border-top:1px dashed var(--ember);opacity:.75}
.step.hush .note{color:var(--ember)}

.spacer{flex:1}
.legend{margin:0 0 4px;font-size:14px;line-height:1.6;color:var(--ink-faint);max-width:64ch}
.key-hush{color:var(--ember);border-bottom:1px dashed var(--ember);padding-bottom:1px}

/* ── fix + footer ─────────────────────────────────────────────────────── */
.fix{border:1px solid var(--rule);border-left:2px solid var(--signal);
  border-radius:4px;background:var(--raise);padding:18px 20px}
.fix .change{font:500 15px/1.5 var(--mono);color:var(--ink)}
.fix .change b{color:var(--signal);font-weight:600}
.fix .why{margin-top:8px;font-size:14px;color:var(--ink-soft)}
.cta{margin-top:56px;padding-top:22px;border-top:1px solid var(--rule);
  display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap}
.cta a{color:var(--violet);text-decoration:none;font-weight:600;
  border-bottom:1px solid currentColor;padding-bottom:1px}
.foot{margin-top:28px;font-size:12.5px;line-height:1.75;color:var(--ink-faint);max-width:76ch}
.foot .mode{color:var(--signal)}
.foot .mode.hybrid{color:var(--amber)}
.foot code{font-family:var(--mono);color:var(--ink-soft)}
.empty{color:var(--ink-soft);font-size:15px;max-width:64ch}

/* ── quality floor ────────────────────────────────────────────────────── */
a:focus-visible,.route:focus-visible{outline:2px solid var(--violet);outline-offset:3px}
@media (max-width:560px){
  .step{min-width:104px}
  .who{font-size:12px;padding:6px 9px}
}
@media (prefers-reduced-motion:no-preference){
  .verdict,.block{animation:rise .5s cubic-bezier(.2,.7,.3,1) both}
  .block:nth-of-type(2){animation-delay:.05s}
  .block:nth-of-type(3){animation-delay:.1s}
  @keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
}

/* ── print ────────────────────────────────────────────────────────────────
   This gets PDF'd and sent to clients. Severity has to survive without a
   single filled background, because browsers drop those by default.        */
@media print{
  :root{--ground:#fff;--raise:#fff;--sunk:#fff;--rule:#c8cedb;--rule-soft:#e2e6ee;
        --ink:#0d1219;--ink-soft:#3d4757;--ink-faint:#6b7688;
        --ember:#b3311a;--signal:#0a6d4a;--amber:#8a5f06;--violet:#4a34b8}
  body{font-size:11pt}
  .wrap{max-width:none;padding:0}
  .route,.fix,.gaps,.action{break-inside:avoid}
  .seam{margin-top:32px}
  .chain{overflow:visible}
  .chain-inner{flex-wrap:wrap;gap:4px 0}
  .cta{display:none}
  .verdict,.block{animation:none}
  a{color:inherit;border-bottom:none}
  .foot{border-top:1px solid var(--rule);padding-top:10px}
}
</style></head>
<body class="v-{{.S.Verdict}}"><div class="wrap">

<header class="mast">
  <div class="wordmark"><b>Harbinger</b> · Attack-path exposure</div>
  <div class="when">{{.Generated}}</div>
</header>

<section class="verdict">
  <span class="status"><span class="dot"></span>{{verdictWord .S.Verdict}}</span>
  <h1 class="finding">{{.S.Headline}}</h1>
</section>

<section class="block">
  <div class="eyebrow">What this means</div>
  <p class="prose">{{.S.Meaning}}</p>
</section>

<section class="block">
  <div class="eyebrow">Do this first</div>
  <div class="action">
    <p>{{.S.Action}}</p>
    {{if .S.Effort}}<p class="caveat">{{.S.Effort}}</p>{{end}}
  </div>
</section>

{{if .S.Scope}}
<section class="block">
  <div class="eyebrow">What was examined</div>
  <ul class="facts">{{range .S.Scope}}<li>{{.}}</li>{{end}}</ul>
</section>
{{end}}

{{if .S.Gaps}}
<section class="block">
  <div class="eyebrow">What this run could not see</div>
  <div class="gaps">
    <p class="lede">A route that was not collected is invisible, not absent. These gaps bound every figure in this report.</p>
    <ul class="facts">{{range .S.Gaps}}<li>{{.}}</li>{{end}}</ul>
  </div>
</section>
{{end}}

<div class="seam"><span>Below: the detail for whoever makes the change</span></div>

{{if .R.Paths}}
<section class="block">
  <div class="eyebrow">Ranked routes to {{.R.CrownName}}
    {{if .Quiet}}· {{.Quiet}} unseen step{{if ne .Quiet 1}}s{{end}} in total{{end}}</div>
  <p class="legend">Each route reads left to right: the account or group on the left can take the
    named action on the one to its right. <span class="key-hush">Dashed steps</span> are ones routine
    monitoring would probably not surface — those are what make a route worth fixing first.</p>
  {{range limit .Top .R.Paths}}
  <article class="route {{if .BlindSpot}}blind{{else}}seen{{end}}">
    <div class="route-head">
      <span class="rank">#{{.Rank}}</span>
      <span>risk <b>{{risk .Risk}}</b></span>
      <span class="sep">/</span>
      <span>{{.Hops}} hop{{if ne .Hops 1}}s{{end}}</span>
      {{with quietHops .}}<span class="sep">/</span><span>{{.}} unseen</span>{{end}}
      <span class="spacer"></span>
      {{if .IsCrown}}<span class="tag crown">Full control</span>{{end}}
      {{if .BlindSpot}}<span class="tag blind">{{pct .Evasion}} likely unseen</span>
      {{else}}<span class="tag seen">{{pct .Evasion}} likely unseen</span>{{end}}
    </div>

    <div class="chain"><div class="chain-inner">
      <div class="hop"><span class="who">{{(index .Steps 0).FromName}}</span></div>
      {{range .Steps}}
      <div class="hop">
        <span class="step {{if quiet .}}hush{{else}}loud{{end}}">
          <span class="what">{{.Edge}}</span>
          <span class="line"></span>
          <span class="note">{{if quiet .}}unseen{{else}}logged{{end}}</span>
        </span>
        <span class="who">{{.ToName}}</span>
      </div>
      {{end}}
    </div></div>
    {{if gt .StartCount 1}}
    <p class="shared">{{sub .StartCount 1}} other principal{{if ne .StartCount 2}}s{{end}} can start
      this same route. One fix closes it for all of them.</p>
    {{end}}
  </article>
  {{end}}
</section>
{{else}}
<section class="block">
  <p class="empty">No route to the crown objective was found in this collection. Read the
  collection gaps above before treating that as a clean result.</p>
</section>
{{end}}

{{if .R.TopFix}}
<section class="block">
  <div class="eyebrow">The change to make</div>
  <div class="fix">
    <div class="change">{{.Fix}}</div>
    <div class="why">Closes {{.R.TopFix.PathsKilled}} of the ranked routes, removing {{risk .R.TopFix.RiskRemoved}} of total risk — {{.R.TopFix.Label}} (<code>{{.R.TopFix.Edge}}</code>).</div>
    <div class="why">Check this against the account's legitimate use before changing it. If it is
      required, reduce its scope instead, then run again to confirm the routes closed.</div>
  </div>
</section>
{{end}}

<div class="cta">
  <div>Take a second snapshot after the change and run <code style="font-family:var(--mono);color:var(--ink-soft)">harbinger diff</code> to confirm the routes closed.</div>
  <a href="https://harbingerlabs.ai">harbingerlabs.ai</a>
</div>

<div class="foot">
  <span class="mode{{if .R.Transmitted}} hybrid{{end}}">{{if .R.Transmitted}}Hybrid scoring — only anonymized, tokenized structural features were transmitted. Raw directory identities never left the machine that produced this report.{{else}}Offline — this report was produced with zero network calls. No data left the machine that produced it.{{end}}</span><br>
  Read-only analysis of an exported file. No credentials were used and live Active Directory was never contacted.
  Scores are structural priors, not guarantees; “likely unseen” assumes common native and endpoint telemetry, not your specific tuned configuration.{{if not .R.Transmitted}} The offline model is a distilled approximation of the calibrated hosted model.{{end}}<br>
  Model <code>{{.R.ModelVersion}}</code> · tier {{.R.Tier}} · scorer {{.R.ScorerName}}
</div>

</div></body></html>`

func fmtPct(f float64) string  { return fmt.Sprintf("%.0f%%", f*100) }
func fmtRisk(f float64) string { return fmt.Sprintf("%.3f", f) }
