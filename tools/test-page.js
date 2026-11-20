#!/usr/bin/env node
// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
/*
 * The page's script (views/OPNsense/UserIdentity/index.volt), run under node with stand-ins for what it
 * reaches of the browser and of OPNsense's page: jQuery as far as the script uses it, UIBootgrid,
 * ajaxGet, ajaxCall, mapDataToFormUI, saveFormToEndpoint and BootstrapDialog. Each lang._() is its
 * English text, as the page shows it without a catalogue.
 *
 * What is checked: the four cards for the status the page is given - the users present with the
 * addresses shared and those two sources clash over; the sources heard, each domain controller named,
 * RADIUS accounting and the captive portal, and what keeps each from being heard (syslog-ng's source not
 * written, no RADIUS client named, no accounting to read, no zone switched on, no session yet, a database
 * that cannot be read, no source chosen); the warning about syslog-ng's source only where domain
 * controllers are named; a status that cannot be read - and the grids' formatters: each mapping's
 * source, a clash and a share; each sender's source and name, and its refusals in the words of its
 * source - a client not named, a user of another directory among them.
 *
 *   node tools/test-page.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.dirname(__dirname);
const VOLT = path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'UserIdentity', 'index.volt');

let failures = 0;
let checks = 0;

function check(name, got, want) {
    checks++;
    const ok = JSON.stringify(got) === JSON.stringify(want);
    if (!ok) {
        failures++;
    }
    console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : ' - got ' + JSON.stringify(got) + ', want ' + JSON.stringify(want)));
}

/* the script between <script> and </script>, each lang._('...') its text */
function script() {
    const text = fs.readFileSync(VOLT, 'utf8').split('<script>')[1].split('</script>')[0];
    return text.replace(/\{\{ lang\._\('((?:[^'\\]|\\.)*)'\) \}\}/g, function (all, said) {
        return said.replace(/\\(.)/g, '$1');
    });
}

function decode(html) {
    return html.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#0?39;/g, "'")
        .replace(/&amp;/g, '&');
}

/* an element as far as the script asks one */
class El {
    constructor(selector) {
        this.selector = selector;
        this.children = [];
        this.classes = [];
        this.attrs = {};
        this.said = '';
        this.shown = null;
        this.handlers = {};
        this.grid = null;
    }

    empty() { this.children = []; this.said = ''; return this; }
    append(child) { this.children.push(child); return this; }
    addClass(names) {
        String(names).split(/\s+/).filter(Boolean).forEach((n) => { if (!this.classes.includes(n)) { this.classes.push(n); } });
        return this;
    }
    removeClass(names) {
        const gone = String(names).split(/\s+/);
        this.classes = this.classes.filter((n) => !gone.includes(n));
        return this;
    }
    attr(name, value) {
        if (value === undefined) {
            return this.attrs[name];
        }
        this.attrs[name] = value;
        if (name === 'class') {
            this.classes = String(value).split(/\s+/).filter(Boolean);
        }
        return this;
    }
    text(value) {
        if (value === undefined) {
            return this.said;
        }
        this.said = String(value);
        return this;
    }
    html(value) {
        if (value === undefined) {
            return this.said;
        }
        this.said = decode(String(value));
        return this;
    }
    toggle(on) { this.shown = !!on; return this; }
    show() { this.shown = true; return this; }
    hide() { this.shown = false; return this; }
    prop() { return this; }
    val() { return ''; }
    click(handler) { this.handlers.click = handler; return this; }
    on(event, handler) { this.handlers[event] = handler; return this; }
    tab() { return this; }
    UIBootgrid(options) { this.grid = options; return this; }
    bootgrid() { return this; }
    selectpicker() { return this; }
}

/* the page, run once with the status it is given */
function page(status) {
    const found = {};
    const ready = [];
    const asked = [];

    function $(what) {
        if (typeof what === 'function') {
            ready.push(what);
            return undefined;
        }
        if (what === sandbox.document) {
            return { ready: (handler) => ready.push(handler) };
        }
        if (what instanceof El) {
            return what;
        }
        if (typeof what === 'string' && what.startsWith('<')) {
            const made = new El(what);
            const cls = what.match(/class="([^"]*)"/);
            return cls ? made.addClass(cls[1]) : made;
        }
        if (!found[what]) {
            found[what] = new El(what);
        }
        return found[what];
    }
    $.each = function (items, handler) {
        if (Array.isArray(items)) {
            items.forEach((value, i) => handler(i, value));
        } else {
            Object.keys(items || {}).forEach((key) => handler(key, items[key]));
        }
    };
    $.map = function (items, handler) {
        const out = [];
        (items || []).forEach((value, i) => {
            const got = handler(value, i);
            if (got !== null && got !== undefined) {
                out.push(got);
            }
        });
        return out;
    };
    const sandbox = {
        $: $,
        document: {},
        window: { location: { hash: '' } },
        history: { pushState: () => undefined },
        console: console,
        ajaxGet: (url, data, done) => { asked.push(url); done(status); },
        ajaxCall: (url) => { asked.push(url); },
        mapDataToFormUI: () => ({ done: (handler) => handler() }),
        saveFormToEndpoint: () => undefined,
        BootstrapDialog: { confirm: () => undefined, TYPE_WARNING: 'warning' }
    };
    vm.createContext(sandbox);
    vm.runInContext(script(), sandbox);
    ready.forEach((handler) => handler());
    return { found: found, asked: asked };
}

/* the cards as [state, key, value, sub] */
function cards(run) {
    return run.found['#ui-cards'].children.map((c) => [c.classes.filter((n) => n !== 'xgs-card').join(' '),
        c.children[1].said, c.children[2].said, c.children[3].said.trim()]);
}

const DC = { kind: 'ad', named: true, address: '192.0.2.10', last_line: 1795100000, last_event: 1795099990, stale: 1, refused: 2 };
const BASE = {
    enabled: true, running: true, project: true, port: 514,
    counts: { users: 3, addresses: 4, shared: 2, clashes: 1 },
    tables: [{ kind: 'group', enabled: true, alias: 'uid_grp_G_Staff', present: true, entries: 2 }],
    ldap: { chosen: 'Example directory', ok: true, chain: 'used' },
    source: { written: true },
    sources: [DC, { kind: 'ad', named: true, address: '192.0.2.11' },
        { kind: 'radius', named: true, address: '192.0.2.40', last_line: 1795100001, last_event: 1795100001, refused: 1 },
        { kind: 'portal', named: true, address: '0', last_line: 1795100002 }],
    radius: { on: true, found: true, sessions: 1, clients: 1 },
    portal: { on: true, found: true, zones: 1, sessions: 2, error: '' },
    listen: [{ interface: 'lan', address: '192.0.2.1' }],
    last_event: 1795100001
};

function status(changes) {
    return Object.assign(JSON.parse(JSON.stringify(BASE)), changes);
}

let run = page(status({}));
let got = cards(run);
check('users present: the clashes between sources said, the card amber',
    got[0], ['warn', 'Users present', '3', '4 addresses · 2 shared · 1 clashes between sources']);
check('sources heard: one of the two domain controllers, RADIUS, the portal', got[2],
    ['warn', 'Sources heard', '3 / 4', 'receiving on port 514']);
check('last event: the latest of every source, the stale and the refused of all', [got[3][0], got[3][1], got[3][3]],
    ['warn', 'Last event', '1 stale · 3 refused']);
check('syslog-ng\'s source written: no warning', run.found['#ui-source'].shown, false);
check('the status asked once, then the grids', run.asked[0], '/api/useridentity/service/status');

run = page(status({ counts: { users: 1, addresses: 1, shared: 0, clashes: 0 }, sources: [DC] , radius: { on: false },
    portal: { on: false } }));
got = cards(run);
check('no clash: the users card green, no word of clashes', got[0], ['ok', 'Users present', '1', '1 addresses · 0 shared']);
check('the domain controllers alone, all heard: green', got[2], ['ok', 'Sources heard', '1 / 1', 'receiving on port 514']);

run = page(status({ sources: [], source: { written: false, reason: 'no domain controller named' },
    radius: { on: true, found: false, clients: 1 }, portal: { on: false } }));
got = cards(run);
check('RADIUS alone, no accounting to read: said, amber', got[2],
    ['warn', 'Sources heard', '0 / 1', 'no RADIUS accounting to read']);
run = page(status({ sources: [], radius: { on: true, found: true, clients: 0 }, portal: { on: false } }));
check('RADIUS on, no client named: said, amber - nothing of RADIUS maps until one is', cards(run)[2],
    ['warn', 'Sources heard', '0 / 1', 'no RADIUS client named']);
check('no domain controller named: no warning about syslog-ng\'s source', run.found['#ui-source'].shown, false);

run = page(status({ sources: [DC], source: { written: false, reason: 'port 5141 on 127.0.0.1 is in use by nginx' },
    radius: { on: false }, portal: { on: false } }));
check('domain controllers named, the source not written: red, the reason said, and the warning shown',
    [cards(run)[2], run.found['#ui-source'].shown],
    [['bad', 'Sources heard', '1 / 1', 'not receiving: port 5141 on 127.0.0.1 is in use by nginx'], true]);

run = page(status({ sources: [], radius: { on: false }, portal: { on: true, found: true, zones: 0 } }));
check('the portal on, no zone switched on: said', cards(run)[2],
    ['warn', 'Sources heard', '0 / 1', 'no captive portal zone switched on']);
run = page(status({ sources: [], radius: { on: false }, portal: { on: true, found: false, zones: 1 } }));
check('the portal on, no session yet: said', cards(run)[2], ['warn', 'Sources heard', '0 / 1', 'no captive portal session yet']);
run = page(status({ sources: [], radius: { on: false }, portal: { on: true, found: true, zones: 1, error: 'database is locked' } }));
check('the portal\'s database that cannot be read: said, with why', cards(run)[2],
    ['warn', 'Sources heard', '0 / 1', 'the portal\'s sessions cannot be read: database is locked']);
run = page(status({ sources: [], radius: { on: false }, portal: { on: false } }));
check('on, and no source chosen: said', cards(run)[2], ['warn', 'Sources heard', '0 / 0', 'no source chosen']);
run = page(status({ enabled: false }));
check('off: the sources card grey, the users card says so', [cards(run)[0].slice(0, 3), cards(run)[2][0], run.found['#ui-off'].shown],
    [['', 'Users present', 'off'], '', true]);
run = page({ error: 'status could not be read' });
check('a status that cannot be read: one red card', cards(run), [['bad', 'User Identity', 'Status could not be read.', '']]);

// the Users tab
run = page(status({}));
const map = run.found['#grid-map'].grid.options.formatters;
check('Users: each mapping\'s source - a domain controller, a RADIUS client, a portal\'s zone by its description or its id',
    [map.source({ id: 'source' }, { kind: 'ad', source: '192.0.2.10' }),
        map.source({ id: 'source' }, { kind: 'radius', source: '192.0.2.40' }),
        map.source({ id: 'source' }, { kind: 'portal', source: '0', source_name: 'Guests' }),
        map.source({ id: 'source' }, { kind: 'portal', source: '2', source_name: '' })],
    ['Active Directory · <code>192.0.2.10</code>', 'RADIUS · <code>192.0.2.40</code>', 'Captive Portal · Guests',
        'Captive Portal · Zone 2']);
check('Users: a clash - each other user with its source; a share; neither',
    [map.shared({ id: 'shared' }, { clash: true, shared: 'user2, user9',
        others: [{ user: 'user2', kind: 'portal' }, { user: 'user9', kind: 'ad' }] }),
    map.shared({ id: 'shared' }, { clash: false, shared: 'user1', others: [{ user: 'user1', kind: 'ad' }] }),
    map.shared({ id: 'shared' }, { clash: false, shared: '', others: [] })],
    ['<span class="text-danger">clash with user2 (Captive Portal), user9 (Active Directory)</span>',
        '<span class="text-warning">shared with user1</span>', '-']);

// the Sources tab
const sources = run.found['#grid-sources'].grid.options.formatters;
check('Sources: each sender\'s source', ['ad', 'radius', 'portal'].map((k) => sources.kind({}, { kind: k })),
    ['Active Directory', 'RADIUS', 'Captive Portal']);
check('Sources: a domain controller, one not named, a RADIUS client, a portal\'s zone',
    [sources.sender({}, { kind: 'ad', address: '192.0.2.10', named: true }),
        sources.sender({}, { kind: 'ad', address: '192.0.2.2', named: false }),
        sources.sender({}, { kind: 'radius', address: '192.0.2.40', named: true }),
        sources.sender({}, { kind: 'portal', address: '0', named: true })],
    ['<span dir="ltr">192.0.2.10</span>', '<span dir="ltr">192.0.2.2</span> <span class="text-warning">not named</span>',
        '<span dir="ltr">192.0.2.40</span>', 'Zone 0']);
check('Sources: the refusals in the words of their source - nobody is no domain user beside the domain controllers',
    [sources.reasons({}, { kind: 'ad', reasons: [{ reason: 'not a user', count: 2 }, { reason: 'computer', count: 1 }] }),
        sources.reasons({}, { kind: 'radius', reasons: [{ reason: 'not a user', count: 1 },
            { reason: 'mac authentication', count: 3 }, { reason: 'something new', count: 1 }] }),
        sources.reasons({}, { kind: 'portal', reasons: [{ reason: 'voucher', count: 1 }] }),
        sources.reasons({}, { kind: 'portal', reasons: [] })],
    ['not a domain user 2 · computer account 1', 'names no user 1 · MAC authentication 3 · something new 1', 'a voucher 1', '-']);
check('Sources: a client not named, and a user of another directory - from RADIUS and from the portal',
    [sources.reasons({}, { kind: 'radius', reasons: [{ reason: 'not a named client', count: 4 },
        { reason: 'another directory', count: 1 }] }),
        sources.reasons({}, { kind: 'portal', reasons: [{ reason: 'another directory', count: 2 }] })],
    ['not a RADIUS client named 4 · a user of another directory 1', 'a user of another directory 2']);

console.log(failures ? failures + ' of ' + checks + ' checks failed' : checks + ' checks passed');
process.exit(failures ? 1 : 0);
