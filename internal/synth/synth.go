// Package synth generates a small, deterministic BloodHound CE export with a
// known low-priv -> Domain Admins path. Used by `harbinger check`, the unit
// tests, and to seed testdata/. It emits NO real data.
package synth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DomainSID is the fixed domain SID of the synthetic forest.
const DomainSID = "S-1-5-21-1111111111-2222222222-3333333333"

func sid(rid int) string { return fmt.Sprintf("%s-%d", DomainSID, rid) }

type file struct {
	Data []map[string]any `json:"data"`
	Meta map[string]any   `json:"meta"`
}

func mk(typ string, data []map[string]any) file {
	return file{Data: data, Meta: map[string]any{"type": typ, "version": 6, "count": len(data)}}
}

// Files returns filename -> JSON bytes for a synthetic export. `fillerUsers`
// pads the graph with unrelated principals to exercise scale/perf.
func Files(fillerUsers int) map[string][]byte {
	daSID := sid(512)

	users := []map[string]any{
		userObj("JON.SNOW@NORTH.LOCAL", sid(1105), true, nil),
		userObj("EDDARD.STARK@NORTH.LOCAL", sid(1111), true, nil),
		userObj("SAMWELL.TARLY@NORTH.LOCAL", sid(1106), true, nil),
		// user with DCSync rights on the domain (GetChanges + GetChangesAll)
		userObj("ROBB.STARK@NORTH.LOCAL", sid(1120), true, nil),
	}
	for i := 0; i < fillerUsers; i++ {
		users = append(users, userObj(fmt.Sprintf("FILLER%04d@NORTH.LOCAL", i), sid(20000+i), true, nil))
	}

	groups := []map[string]any{
		// Domain Admins (RID 512) — the crown. Member: eddard.stark.
		groupObj("DOMAIN ADMINS@NORTH.LOCAL", daSID, []string{sid(1111)}),
		// Night's Watch — jon.snow is a member.
		groupObj("NIGHT'S WATCH@NORTH.LOCAL", sid(1201), []string{sid(1105)}),
	}

	computers := []map[string]any{
		// WINTERFELL: Night's Watch has GenericAll; eddard has a live session.
		computerObj("WINTERFELL.NORTH.LOCAL", sid(1301),
			[]ace{{sid(1201), "GenericAll"}},
			[]session{{User: sid(1111), Comp: sid(1301)}}),
	}

	domains := []map[string]any{
		domainObj("NORTH.LOCAL", DomainSID, []ace{
			{sid(1120), "GetChanges"},
			{sid(1120), "GetChangesAll"},
		}),
	}

	out := map[string][]byte{}
	out["users.json"] = must(mk("users", users))
	out["groups.json"] = must(mk("groups", groups))
	out["computers.json"] = must(mk("computers", computers))
	out["domains.json"] = must(mk("domains", domains))
	return out
}

// WriteDir writes a synthetic export to dir (created if needed).
func WriteDir(dir string, fillerUsers int) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, b := range Files(fillerUsers) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

type ace struct {
	principal string
	right     string
}
type session struct {
	User, Comp string
}

func userObj(name, id string, enabled bool, aces []ace) map[string]any {
	return map[string]any{
		"ObjectIdentifier": id,
		"Properties": map[string]any{
			"name": name, "domainsid": DomainSID, "objectid": id, "enabled": enabled,
		},
		"Aces": acesJSON(aces),
	}
}

func groupObj(name, id string, members []string) map[string]any {
	var mm []map[string]any
	for _, m := range members {
		mm = append(mm, map[string]any{"ObjectIdentifier": m, "ObjectType": "User"})
	}
	return map[string]any{
		"ObjectIdentifier": id,
		"Properties":       map[string]any{"name": name, "domainsid": DomainSID, "objectid": id},
		"Members":          mm,
	}
}

func computerObj(name, id string, aces []ace, sessions []session) map[string]any {
	var ss []map[string]any
	for _, s := range sessions {
		ss = append(ss, map[string]any{"UserSID": s.User, "ComputerSID": s.Comp})
	}
	return map[string]any{
		"ObjectIdentifier": id,
		"Properties":       map[string]any{"name": name, "domainsid": DomainSID, "objectid": id, "enabled": true},
		"Aces":             acesJSON(aces),
		"Sessions":         map[string]any{"Collected": true, "Results": ss},
	}
}

func domainObj(name, id string, aces []ace) map[string]any {
	return map[string]any{
		"ObjectIdentifier": id,
		"Properties":       map[string]any{"name": name, "domainsid": id, "objectid": id},
		"Aces":             acesJSON(aces),
	}
}

func acesJSON(aces []ace) []map[string]any {
	var out []map[string]any
	for _, a := range aces {
		out = append(out, map[string]any{
			"PrincipalSID": a.principal, "PrincipalType": "Group", "RightName": a.right, "IsInherited": false,
		})
	}
	return out
}

func must(f file) []byte {
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		panic(err)
	}
	return b
}
