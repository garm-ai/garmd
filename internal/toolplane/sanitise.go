package toolplane

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	toolv1 "github.com/garm-ai/garm/contracts/garm/tool/v1"
	"github.com/garm-ai/garm/policy"
)

// The one type garmd knows by name.
//
// This is invariant 2 reconciled rather than bent (cards-and-tasks design
// §3.1). garmd does not learn about agents, tools or tasks; it learns a TYPE,
// the way it already knows google.protobuf.Timestamp is a value and not a
// structure to classify. What is special about this one is that INSIDE it the
// policy is carried by the VALUE rather than by the descriptor — a queue, or
// a card built from another tool's material, cannot know at compile time
// which row is whose — so the per-message plan cannot express it and a walk
// over the value must.
//
// Nothing else in garm.card.v1 is read. Not the templates, not card_role, not
// the kinds: garmd cannot tell a task card from a start card and does not
// need to.
const (
	cardMessageName  protoreflect.FullName = "garm.card.v1.Card"
	labelMessageName protoreflect.FullName = "garm.card.v1.Label"
)

// The field numbers the design fixes (§1.1), pinned here and asserted against
// internal/toolplane/testdata/card.proto.
//
// They are a SECOND opinion, not the lookup: every read below finds the field
// by NAME and then checks that the number agrees, so a contract that renumbers
// without renaming is caught rather than silently misread, and a contract that
// renames is caught too. garm v0.16.0 ships neither `access` nor `Label`;
// Track G adds both. See KNOWN-GAPS.md.
const (
	fieldNumCardAccess    protoreflect.FieldNumber = 10
	fieldNumElementAccess protoreflect.FieldNumber = 10
	fieldNumFactAccess    protoreflect.FieldNumber = 4
	fieldNumChoiceAccess  protoreflect.FieldNumber = 3

	fieldNumLabelClearance    protoreflect.FieldNumber = 1
	fieldNumLabelCompartments protoreflect.FieldNumber = 2
)

// pinnedAccessNumbers is the pin above, keyed by the message that carries the
// field. A message not named here (Action, CardRef, and whatever Track G adds
// next) is read by name with no number to check it against — the walk is
// generic over "carries an access label", and the pin is only as wide as the
// design wrote it down.
var pinnedAccessNumbers = map[protoreflect.FullName]protoreflect.FieldNumber{
	"garm.card.v1.Card":    fieldNumCardAccess,
	"garm.card.v1.Element": fieldNumElementAccess,
	"garm.card.v1.Fact":    fieldNumFactAccess,
	"garm.card.v1.Choice":  fieldNumChoiceAccess,
}

// accessFieldName and labelField* are the NAMES. Track G chooses the numbers;
// it does not get to choose these without the tests saying so.
const (
	accessFieldName            protoreflect.Name = "access"
	factSourceFieldName        protoreflect.Name = "field"
	labelClearanceFieldName    protoreflect.Name = "clearance"
	labelCompartmentsFieldName protoreflect.Name = "compartments"
	disclosureFieldName        protoreflect.Name = "disclosure"
	withheldFieldsFieldName    protoreflect.Name = "withheld_fields"
)

// isCardMessage reports whether md is THE card.
func isCardMessage(md protoreflect.MessageDescriptor) bool {
	return md != nil && md.FullName() == cardMessageName
}

// accessFieldOf returns the label field a message carries, or nil.
//
// By NAME, because the number is Track G's to pick and the design fixes the
// name. The number is checked separately, by pinViolation, and checked as a
// REFUSAL rather than folded in here: a message whose `access` moved must not
// read as "unlabelled", because unlabelled means "read at the endpoint's
// floor" — which the caller has already passed — and a drifted contract would
// then publish every element it labelled.
func accessFieldOf(md protoreflect.MessageDescriptor) protoreflect.FieldDescriptor {
	if md == nil {
		return nil
	}
	fd := md.Fields().ByName(accessFieldName)
	if fd == nil {
		return nil
	}
	if fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
		return nil
	}
	if fd.Message().FullName() != labelMessageName {
		return nil
	}
	return fd
}

// pinViolation reports a card vocabulary this build has not been tested
// against, as a sentence for the ledger — or "" when the shape agrees.
//
// Two ways to disagree. A pinned message whose `access` sits at a different
// number, and the Card itself carrying no `access` garmd recognises at all:
// the first would be read against a label nobody verified, the second means
// the label was renamed or removed and every element would silently fall back
// to the endpoint's floor. Both refuse the card. This is the whole of what
// stands between the fixture's assumption and a contract that moved.
func pinViolation(md protoreflect.MessageDescriptor) string {
	fd := accessFieldOf(md)
	if fd == nil {
		if isCardMessage(md) {
			return fmt.Sprintf("no_access_label: %s carries no `access` of type %s, "+
				"so this build cannot project it", md.FullName(), labelMessageName)
		}
		return ""
	}
	if want, pinned := pinnedAccessNumbers[md.FullName()]; pinned && fd.Number() != want {
		return fmt.Sprintf("access_field_moved: %s.access is field %d, want %d",
			md.FullName(), fd.Number(), want)
	}
	return ""
}

// containsCard reports whether a Card is reachable from md.
//
// Cycle-guarded, because garm.card.v1 IS recursive (Element → Section →
// Element) and this is asked of descriptors that contain one.
func containsCard(md protoreflect.MessageDescriptor) bool {
	return reachesCard(md, map[protoreflect.FullName]bool{})
}

func reachesCard(md protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) bool {
	if md == nil || seen[md.FullName()] {
		return false
	}
	if isCardMessage(md) {
		return true
	}
	seen[md.FullName()] = true
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		child, ok := policy.SubtreeOf(fields.Get(i))
		if ok && reachesCard(child, seen) {
			return true
		}
	}
	return false
}

// compilePlan is the per-message plan, with one rule added to policy.Compile:
// a Card is an opaque leaf.
//
// It has to be. policy.Compile flattens a message graph into a finite list of
// field paths and REFUSES a cycle, and garm.card.v1 is cyclic by construction
// — a Section holds Elements. Every field of a card's interior is also
// unannotated, because a card's policy is on the value and not on the
// descriptor, so even an acyclic card would fail Compile's "field has no
// policy and no message default". Descending into a card is therefore not
// merely unnecessary, it is impossible; and treating it as a leaf is the same
// judgement policy.IsOpaqueLeafMessage already makes about a Timestamp, for a
// reason that is closer than it looks: the field's own policy governs the
// whole value, and what is INSIDE is governed by something else — here, by
// the card walk at step 8.
//
// A response that IS a Card gets an EMPTY plan. That is the design's own
// sentence (§10.3 frame 7: "field plan: Card has no policied scalar fields"),
// and the card walk is the whole of its enforcement.
func (c *Core) compilePlan(md protoreflect.MessageDescriptor) (*policy.Plan, error) {
	if isCardMessage(md) {
		return &policy.Plan{Desc: md}, nil
	}
	if !containsCard(md) {
		return policy.Compile(md, c.reg)
	}
	p := &policy.Plan{Desc: md}
	if err := compileAroundCards(p, md, c.reg, nil, "", map[protoreflect.FullName]bool{}); err != nil {
		return nil, err
	}
	return p, nil
}

// compileAroundCards mirrors policy.Compile's walk, stopping at a Card.
//
// It is a mirror rather than a wrapper because policy.Compile offers no seam
// to stop at: the walk is one unexported function. Everything it decides —
// which policy a field carries, which compartments that resolves to, what
// counts as a subtree — is still policy's, called here, so the only thing
// this copy owns is the one extra line that refuses to descend into a card.
func compileAroundCards(
	p *policy.Plan,
	md protoreflect.MessageDescriptor,
	reg *policy.Registry,
	path []protoreflect.FieldNumber,
	prefix string,
	seen map[protoreflect.FullName]bool,
) error {
	if seen[md.FullName()] {
		at := "(root)"
		if prefix != "" {
			at = prefix
		}
		return fmt.Errorf("%s: recursive message type reached again at %q: a cycle "+
			"cannot be flattened into a finite plan", md.FullName(), at)
	}
	seen[md.FullName()] = true
	defer delete(seen, md.FullName())

	def := policy.MessageDefaultPolicy(md)
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		fp := policy.FieldPolicyOf(fd, def)
		if fp == nil {
			return fmt.Errorf("%s: field %q has no policy and no message default",
				md.FullName(), fd.Name())
		}
		need, err := reg.Set(fp.GetCompartments())
		if err != nil {
			return fmt.Errorf("%s.%s: %w", md.FullName(), fd.Name(), err)
		}

		name := string(fd.Name())
		if prefix != "" {
			name = prefix + "." + name
		}

		childMD, descend := policy.SubtreeOf(fd)
		if descend && isCardMessage(childMD) {
			// The leaf. The field's own policy still governs the whole card
			// as a value — policy.Sanitize will drop it outright for a caller
			// the field denies — and what is inside it is the card walk's.
			descend = false
		}

		write := fp.GetWrite()
		if write == toolv1.Clearance_CLEARANCE_UNSPECIFIED {
			write = fp.GetRead()
		}
		p.Actions = append(p.Actions, policy.Action{
			Path:        append(append([]protoreflect.FieldNumber{}, path...), fd.Number()),
			Name:        name,
			Read:        fp.GetRead(),
			Write:       write,
			Need:        need,
			OnDeny:      fp.GetOnDeny(),
			IsSubtree:   descend,
			AuditOnRead: fp.GetAuditOnRead(),
		})
		if descend {
			child := append(append([]protoreflect.FieldNumber{}, path...), fd.Number())
			if err := compileAroundCards(p, childMD, reg, child, name, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- the walk

// cardFloor is the policy an element may not be labelled below, and the
// policy an UNLABELLED element takes.
//
// It is the join of two things, and it is a join because the design says both
// and neither subsumes the other: the response message's own default field
// policy (what the contract says about this message), and the card endpoint's
// own min_clearance and compartments (§3.2 floor 1, §10.3 frame 7 — "every
// label ≥ endpoint policy"). Joining takes the higher clearance and the union
// of compartments, so the floor is never looser than either.
//
// "Absent means the endpoint's policy, never PUBLIC" (§1.1) falls out of this
// rather than being a second rule: an unlabelled element is read at the floor,
// and the floor is PUBLIC only where the endpoint itself is.
type cardFloor struct {
	clearance    toolv1.Clearance
	compartments []string
}

func (c *Core) floorFor(t ToolDef, md protoreflect.MessageDescriptor) cardFloor {
	f := cardFloor{clearance: t.MinClearance, compartments: append([]string(nil), t.Compartments...)}
	if def := policy.MessageDefaultPolicy(md); def != nil {
		if def.GetRead() > f.clearance {
			f.clearance = def.GetRead()
		}
		for _, name := range def.GetCompartments() {
			if !containsString(f.compartments, name) {
				f.compartments = append(f.compartments, name)
			}
		}
	}
	return f
}

// label is one `access` value, read off a card.
type label struct {
	clearance    toolv1.Clearance
	compartments []string
}

// cardResult is what the walk decided, for step 8 to act on.
type cardResult struct {
	// withheld is what to name in Disclosure and on the ledger row: paths,
	// or a Fact's own `field`, never a value.
	withheld []string

	// invalid, when set, is floor 1 firing: an element labelled below the
	// endpoint's own policy. It names the check and the path, for the log and
	// the ledger's error_detail. The whole call is refused; there is never a
	// partial card.
	invalid string

	// gone means the ANSWER itself was withheld whole — a unary Card whose
	// own access this viewer does not reach. The caller gets NotFound, the
	// same closed answer step 2 gives for a tool they may not see.
	gone bool
}

// projectCards is the card walk: step 8's second half, after the field plan.
func (c *Core) projectCards(p *Principal, t ToolDef, resp proto.Message) cardResult {
	w := &cardWalk{core: c, principal: p, floor: c.floorFor(t, resp.ProtoReflect().Descriptor())}

	// Validation first, over the WHOLE tree, before anything is removed.
	// Floor 1 refuses the entire call, so a card that is going to be refused
	// must not have been half-projected on the way to finding out.
	w.validate(resp.ProtoReflect(), "")
	if w.invalid != "" {
		return cardResult{invalid: w.invalid}
	}

	gone := w.forEachCard(resp.ProtoReflect(), "", w.projectCard)
	return cardResult{withheld: w.withheld, gone: gone}
}

type cardWalk struct {
	core      *Core
	principal *Principal
	floor     cardFloor

	withheld []string
	invalid  string
}

// forEachCard applies fn to every Card in m and reports whether the message
// IS a card that fn withheld.
//
// Three shapes, because the design has three (§3.1): the response IS a Card;
// a field of it is one; a repeated field of it is a list of them (list_tasks
// returns a page of cards). A card withheld from a list is DROPPED from the
// list; a singular card field is cleared; the unary answer is the caller's
// NotFound, decided by the caller of this function.
func (w *cardWalk) forEachCard(
	m protoreflect.Message, path string, fn func(protoreflect.Message, string) bool,
) bool {
	if isCardMessage(m.Descriptor()) {
		return !fn(m, path)
	}
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		child, ok := policy.SubtreeOf(fd)
		if !ok || !m.Has(fd) || !containsCard(child) {
			continue
		}
		switch {
		case fd.IsMap():
			// No map of cards exists in the contract, and inventing a path
			// naming for one would be guessing. Left alone deliberately: a
			// map field of cards must be added here before it can be served.
			continue
		case fd.IsList():
			idx := 0
			w.filterList(m, fd, func(el protoreflect.Message) bool {
				p := indexPath(path, string(fd.Name()), idx)
				idx++
				if isCardMessage(el.Descriptor()) {
					return fn(el, p)
				}
				w.forEachCard(el, p, fn)
				return true
			})
		default:
			p := namePath(path, string(fd.Name()))
			sub := m.Mutable(fd).Message()
			if isCardMessage(sub.Descriptor()) {
				if !fn(sub, p) {
					m.Clear(fd)
				}
				continue
			}
			w.forEachCard(sub, p, fn)
		}
	}
	return false
}

// projectCard applies rule 1 to one card, and reports whether it survives.
func (w *cardWalk) projectCard(card protoreflect.Message, path string) bool {
	if !w.reaches(card) {
		w.note(card, path)
		return false
	}
	// The card's own body. A card whose every element is withheld is still a
	// card: the viewer reached it, and an empty card with a Disclosure is a
	// truthful answer where a NotFound would not be. Only a SECTION collapses
	// (§3.2 rule 1), which is projectNode's rule and not this one.
	//
	// The Disclosure is per CARD, so the entries this card's own walk added
	// are the ones it carries — a page of cards does not hand each of them
	// the paths withheld from its neighbours.
	mark := len(w.withheld)
	w.projectChildren(card, "")
	w.recordDisclosure(card, w.withheld[mark:])
	return true
}

// projectNode projects one labelled node and reports whether it survives.
func (w *cardWalk) projectNode(m protoreflect.Message, path string) bool {
	if !w.reaches(m) {
		w.note(m, path)
		return false
	}
	mark := len(w.withheld)
	kept, total := w.projectChildren(m, path)
	if total > 0 && kept == 0 {
		// "A Section whose every child is withheld is withheld whole." The
		// children's own entries are replaced by the parent's rather than
		// listed beside it: the viewer is told one thing was withheld,
		// because from where they stand one thing was.
		w.withheld = w.withheld[:mark]
		w.note(m, path)
		return false
	}
	return true
}

// projectChildren walks m's message-valued fields, projecting every labelled
// descendant. It returns how many labelled children survived and how many
// there were.
//
// A message with no `access` of its own is TRANSPARENT: the walk descends
// through it without extending the path, which is what makes an element's
// path read `body[2].facts[1]` rather than `body[2].facts.facts[1]` — a
// FactSet is a container in the vocabulary, not a position in the layout.
func (w *cardWalk) projectChildren(m protoreflect.Message, path string) (kept, total int) {
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		child, ok := policy.SubtreeOf(fd)
		if !ok || fd.IsMap() || !m.Has(fd) {
			continue
		}
		if fd.Message() != nil && fd.Message().FullName() == labelMessageName {
			continue // the node's own label, not a child of it
		}
		labelled := accessFieldOf(child) != nil

		if fd.IsList() {
			if labelled {
				before := m.Get(fd).List().Len()
				survived := 0
				idx := 0
				w.filterList(m, fd, func(el protoreflect.Message) bool {
					p := indexPath(path, string(fd.Name()), idx)
					idx++
					keep := w.projectNode(el, p)
					if keep {
						survived++
					}
					return keep
				})
				total += before
				kept += survived
				continue
			}
			list := m.Get(fd).List()
			for j := 0; j < list.Len(); j++ {
				k, t := w.projectChildren(list.Get(j).Message(), path)
				kept += k
				total += t
			}
			continue
		}

		sub := m.Mutable(fd).Message()
		if labelled {
			total++
			p := namePath(path, string(fd.Name()))
			if w.projectNode(sub, p) {
				kept++
			} else {
				m.Clear(fd)
			}
			continue
		}
		k, t := w.projectChildren(sub, path)
		kept += k
		total += t
	}
	return kept, total
}

// filterList rewrites a repeated message field, keeping what fn returns true
// for. Nothing is written back unless something was dropped.
func (w *cardWalk) filterList(
	m protoreflect.Message, fd protoreflect.FieldDescriptor,
	keep func(protoreflect.Message) bool,
) {
	list := m.Mutable(fd).List()
	survivors := make([]protoreflect.Value, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		el := list.Get(i).Message()
		if !keep(el) {
			continue
		}
		// Cloned before the truncate below, because the elements are views
		// into the list being rewritten.
		survivors = append(survivors,
			protoreflect.ValueOfMessage(proto.Clone(el.Interface()).ProtoReflect()))
	}
	if len(survivors) == list.Len() {
		return
	}
	list.Truncate(0)
	for _, v := range survivors {
		list.Append(v)
	}
}

// validate is floor 1, over every labelled node of every card in the message.
//
// It reads and never writes. The first violation wins and names itself; there
// is no list, because the answer is the same for one as for ten — the whole
// card is refused — and an operator fixing the first will see the second.
func (w *cardWalk) validate(m protoreflect.Message, path string) {
	if w.invalid != "" {
		return
	}
	if v := pinViolation(m.Descriptor()); v != "" {
		w.invalid = v
		return
	}
	if fd := accessFieldOf(m.Descriptor()); fd != nil && m.Has(fd) {
		lbl, ok := readLabel(m.Get(fd).Message())
		switch {
		case !ok:
			w.invalid = "unreadable_label: " + orRoot(path)
			return
		case lbl.clearance < w.floor.clearance:
			w.invalid = "label_below_endpoint: " + orRoot(path)
			return
		case !coversNames(lbl.compartments, w.floor.compartments):
			w.invalid = "label_below_endpoint: " + orRoot(path)
			return
		}
	}
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		child, ok := policy.SubtreeOf(fd)
		if !ok || fd.IsMap() || !m.Has(fd) {
			continue
		}
		if fd.Message() != nil && fd.Message().FullName() == labelMessageName {
			continue
		}
		labelled := accessFieldOf(child) != nil
		if fd.IsList() {
			list := m.Get(fd).List()
			for j := 0; j < list.Len(); j++ {
				p := path
				if labelled {
					p = indexPath(path, string(fd.Name()), j)
				}
				w.validate(list.Get(j).Message(), p)
				if w.invalid != "" {
					return
				}
			}
			continue
		}
		p := path
		if labelled {
			p = namePath(path, string(fd.Name()))
		}
		w.validate(m.Get(fd).Message(), p)
		if w.invalid != "" {
			return
		}
	}
}

// reaches is the same predicate field projection uses: clearance at or above,
// and every compartment held.
//
// An UNLABELLED node is read at the floor rather than waved through, which is
// the whole of "absent means the endpoint's policy, never PUBLIC".
func (w *cardWalk) reaches(m protoreflect.Message) bool {
	lbl := label{clearance: w.floor.clearance, compartments: w.floor.compartments}
	if fd := accessFieldOf(m.Descriptor()); fd != nil && m.Has(fd) {
		read, ok := readLabel(m.Get(fd).Message())
		if !ok {
			return false // validate refused this already; fail closed anyway
		}
		lbl = read
	}
	if !policy.Allows(w.principal.Clearance, lbl.clearance) {
		return false
	}
	need, err := w.core.reg.Set(lbl.compartments)
	if err != nil {
		// A compartment nobody declared is one nobody holds. Refusing reach
		// is the closed answer; dropping the name would WIDEN the element's
		// audience, which is the one direction this must never fail in.
		return false
	}
	return w.principal.Compartments.Covers(need)
}

// note records a withheld element by path, or by a Fact's own `field` when it
// has one — never by value, and never by the value's caption.
func (w *cardWalk) note(m protoreflect.Message, path string) {
	name := orRoot(path)
	if fd := m.Descriptor().Fields().ByName(factSourceFieldName); fd != nil &&
		fd.Kind() == protoreflect.StringKind && !fd.IsList() && m.Has(fd) {
		if v := m.Get(fd).String(); v != "" {
			name = v
		}
	}
	w.withheld = append(w.withheld, name)
}

// recordDisclosure writes what was withheld from THIS card onto the card, so
// the viewer's renderer can say so. Appended to whatever the tool already
// declared: a tool that knew it was serving less than everything said so, and
// this adds what garmd took.
func (w *cardWalk) recordDisclosure(card protoreflect.Message, withheld []string) {
	if len(withheld) == 0 {
		return
	}
	fd := card.Descriptor().Fields().ByName(disclosureFieldName)
	if fd == nil || fd.Kind() != protoreflect.MessageKind || fd.IsList() {
		return
	}
	d := card.Mutable(fd).Message()
	wf := d.Descriptor().Fields().ByName(withheldFieldsFieldName)
	if wf == nil || !wf.IsList() || wf.Kind() != protoreflect.StringKind {
		return
	}
	list := d.Mutable(wf).List()
	for _, name := range withheld {
		list.Append(protoreflect.ValueOfString(name))
	}
}

// readLabel reads a Label by field NAME, checking the numbers against the pin.
func readLabel(m protoreflect.Message) (label, bool) {
	md := m.Descriptor()
	cl := md.Fields().ByName(labelClearanceFieldName)
	cm := md.Fields().ByName(labelCompartmentsFieldName)
	if cl == nil || cl.Kind() != protoreflect.EnumKind || cl.Number() != fieldNumLabelClearance {
		return label{}, false
	}
	if cm == nil || !cm.IsList() || cm.Kind() != protoreflect.StringKind ||
		cm.Number() != fieldNumLabelCompartments {
		return label{}, false
	}
	out := label{clearance: toolv1.Clearance(m.Get(cl).Enum())}
	list := m.Get(cm).List()
	for i := 0; i < list.Len(); i++ {
		out.compartments = append(out.compartments, list.Get(i).String())
	}
	return out, true
}

// coversNames reports whether have contains every name in need.
func coversNames(have, need []string) bool {
	for _, n := range need {
		if !containsString(have, n) {
			return false
		}
	}
	return true
}

func namePath(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func indexPath(path, name string, i int) string {
	return fmt.Sprintf("%s[%d]", namePath(path, name), i)
}

func orRoot(path string) string {
	if strings.TrimSpace(path) == "" {
		return "(card)"
	}
	return path
}
