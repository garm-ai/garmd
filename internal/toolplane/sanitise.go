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
		child, ok := cardChildOf(fields.Get(i))
		if ok && reachesCard(child, seen) {
			return true
		}
	}
	return false
}

// cardChildOf reports whether the card walk descends into fd, and into which
// message.
//
// It is deliberately NOT policy.SubtreeOf. Since garm v0.17.0 that function
// stops at a `garm.card.v1.Card`, because the FIELD PLAN treats a card as an
// opaque value — which is right, and is the half of the work this daemon
// needed from the contract. The card walk is the other half and has the
// opposite job: a card is precisely what it is looking for, so it has to
// descend where the field plan stops. Sharing one predicate between the two
// would make each release of garm's policy package a silent change to which
// cards get projected, and the failure would look like a card served whole.
//
// Well-known types are skipped for the ordinary reason: they hold no labels
// and no cards, and a Timestamp is a value.
func cardChildOf(fd protoreflect.FieldDescriptor) (protoreflect.MessageDescriptor, bool) {
	if fd.Kind() != protoreflect.MessageKind {
		return nil, false
	}
	md := fd.Message()
	if fd.IsMap() {
		if fd.MapValue().Kind() != protoreflect.MessageKind {
			return nil, false
		}
		md = fd.MapValue().Message()
	}
	if md == nil || strings.HasPrefix(string(md.FullName()), "google.protobuf.") {
		return nil, false
	}
	return md, true
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

	// check names WHICH floor this is, for the ledger: the endpoint's, a
	// Section's, or an enclosing element's. An operator reading
	// `label_below_section: body[0].elements[1]` knows where to look; one
	// reading `label_below_endpoint` for the same element would go and check
	// the tool's min_clearance and find nothing wrong with it.
	check string
}

// under returns the floor that applies INSIDE a labelled node.
//
// A labelled element is a floor for everything it contains. For a Section
// that is the contract saying so — "a child may be labelled higher, never
// lower" — and lint C8 checks it at publish time, but lint can only see a
// TEMPLATE: a card an override built by hand has no template to lint, and it
// reaches a viewer all the same. So the same rule is enforced here, per call,
// where every card passes whatever built it.
//
// It is applied to every labelled element and not only to a Section because
// the rule is the same one and the narrower version would be a special case
// for a message name: a reader who cannot see the thing a fact is inside
// cannot be shown the fact, whether the container was titled or not.
func (f cardFloor) under(l label, isSection bool) cardFloor {
	out := cardFloor{clearance: f.clearance, compartments: f.compartments, check: labelBelowElement}
	if isSection {
		out.check = labelBelowSection
	}
	if l.clearance > out.clearance {
		out.clearance = l.clearance
	}
	for _, name := range l.compartments {
		if !containsString(out.compartments, name) {
			out.compartments = append(append([]string(nil), out.compartments...), name)
		}
	}
	return out
}

// admits reports whether a label is AT OR ABOVE this floor.
func (f cardFloor) admits(l label) bool {
	return l.clearance >= f.clearance && coversNames(l.compartments, f.compartments)
}

// The three floors, as they read on a ledger row.
const (
	labelBelowEndpoint = "label_below_endpoint"
	labelBelowSection  = "label_below_section"
	labelBelowElement  = "label_below_element"
)

// sectionMessageName is read for ONE thing only: which of the three names
// above a refusal carries. Nothing about the projection depends on it — a
// Section is projected by the same rule as every other labelled element —
// so this is diagnostics, not policy.
const sectionMessageName protoreflect.FullName = "garm.card.v1.Section"

// holdsASection reports whether a labelled element's payload is a Section.
func holdsASection(m protoreflect.Message) bool {
	var found bool
	m.Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		if fd.Kind() == protoreflect.MessageKind && !fd.IsList() && !fd.IsMap() &&
			fd.Message() != nil && fd.Message().FullName() == sectionMessageName {
			found = true
		}
		return !found
	})
	return found
}

func (c *Core) floorFor(t ToolDef, md protoreflect.MessageDescriptor) cardFloor {
	f := cardFloor{
		clearance:    t.MinClearance,
		compartments: append([]string(nil), t.Compartments...),
		check:        labelBelowEndpoint,
	}
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
	w := &cardWalk{core: c, principal: p}
	floor := c.floorFor(t, resp.ProtoReflect().Descriptor())

	// Validation first, over the WHOLE tree, before anything is removed.
	// Floor 1 refuses the entire call, so a card that is going to be refused
	// must not have been half-projected on the way to finding out.
	w.validate(resp.ProtoReflect(), "", floor)
	if w.invalid != "" {
		return cardResult{invalid: w.invalid}
	}

	gone := w.forEachCard(resp.ProtoReflect(), "",
		func(card protoreflect.Message, path string) bool {
			return w.projectCard(card, path, floor)
		})
	return cardResult{withheld: w.withheld, gone: gone}
}

type cardWalk struct {
	core      *Core
	principal *Principal

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
		child, ok := cardChildOf(fd)
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
func (w *cardWalk) projectCard(card protoreflect.Message, path string, floor cardFloor) bool {
	if !w.reaches(card, floor) {
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
	w.projectChildren(card, "", w.floorInside(card, floor))
	w.recordDisclosure(card, w.withheld[mark:])
	return true
}

// floorInside is the floor that applies to a labelled node's children: its
// own label when it has one, the inherited floor when it does not.
func (w *cardWalk) floorInside(m protoreflect.Message, floor cardFloor) cardFloor {
	fd := accessFieldOf(m.Descriptor())
	if fd == nil || !m.Has(fd) {
		return floor
	}
	lbl, ok := readLabel(m.Get(fd).Message())
	if !ok {
		return floor
	}
	return floor.under(lbl, holdsASection(m))
}

// projectNode projects one labelled node and reports whether it survives.
func (w *cardWalk) projectNode(m protoreflect.Message, path string, floor cardFloor) bool {
	if !w.reaches(m, floor) {
		w.note(m, path)
		return false
	}
	mark := len(w.withheld)
	kept, total := w.projectChildren(m, path, w.floorInside(m, floor))
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
// GENERIC over "this message carries an access label", not over a list of
// message names. That is what makes `body`, `actions`, `refs` and the
// interior of an `Input` one rule instead of four: a Choice inside a
// ChoiceInput inside an Input inside an Element is reached by the same walk
// that reaches a Fact inside a FactSet, and the day the contract labels an
// Action nothing here changes. It is also why nothing here mentions a Section
// — a Section is a message with labelled children, and "withheld whole when
// every child went" is a property of that, not of its name.
//
// A message with no `access` of its own is TRANSPARENT: the walk descends
// through it without extending the path, which is what makes an element's
// path read `body[2].facts[1]` rather than `body[2].facts.facts[1]` — a
// FactSet is a container in the vocabulary, not a position in the layout.
func (w *cardWalk) projectChildren(
	m protoreflect.Message, path string, floor cardFloor,
) (kept, total int) {
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		child, ok := cardChildOf(fd)
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
					keep := w.projectNode(el, p, floor)
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
				k, t := w.projectChildren(list.Get(j).Message(), path, floor)
				kept += k
				total += t
			}
			continue
		}

		sub := m.Mutable(fd).Message()
		if labelled {
			total++
			p := namePath(path, string(fd.Name()))
			if w.projectNode(sub, p, floor) {
				kept++
			} else {
				m.Clear(fd)
			}
			continue
		}
		k, t := w.projectChildren(sub, path, floor)
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

// validate is the floors, over every labelled node of every card.
//
// There are two, and they are the same rule applied at two scopes. The
// ENDPOINT floor (§3.2 floor 1): no element may be labelled below the policy
// the card endpoint is already gated at. The ENCLOSING floor: no element may
// be labelled below the element that contains it — the contract's "a Section
// is a floor for its children; higher, never lower", which lint C8 checks on
// a TEMPLATE at publish time and which has to be checked HERE as well,
// because a card an override built by hand has no template to lint and
// reaches a viewer all the same. A reader who cannot see the heading must not
// be shown what was under it.
//
// It reads and never writes. The first violation wins and names itself; there
// is no list, because the answer is the same for one as for ten — the whole
// card is refused — and an operator fixing the first will see the second.
func (w *cardWalk) validate(m protoreflect.Message, path string, floor cardFloor) {
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
		case !floor.admits(lbl):
			w.invalid = floor.check + ": " + orRoot(path)
			return
		}
		// Everything below this node is under ITS label now.
		floor = floor.under(lbl, holdsASection(m))
	}
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		child, ok := cardChildOf(fd)
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
				w.validate(list.Get(j).Message(), p, floor)
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
		w.validate(m.Get(fd).Message(), p, floor)
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
func (w *cardWalk) reaches(m protoreflect.Message, floor cardFloor) bool {
	lbl := label{clearance: floor.clearance, compartments: floor.compartments}
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
