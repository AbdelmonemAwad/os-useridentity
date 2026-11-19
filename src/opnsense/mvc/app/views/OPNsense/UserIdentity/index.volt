{#
 # SPDX-License-Identifier: BSD-2-Clause
 # Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 #
 # Firewall: User Identity (XGS: User Identity when os-xgs-npu is installed) - which user each address
 # belongs to, from the domain controllers' logon events, RADIUS accounting and the captive portal's
 # sessions - the latest wins, and two sources that clash over an address are shown - the tables of
 # groups and users that follow from it, the sources heard, and the settings.
 #}

<style>
    /* KIT-CSS-BEGIN */
    .xgs-cards { display: flex; flex-wrap: wrap; gap: 12px; padding: 15px; }
    .xgs-cards.xgs-top { padding: 0 0 15px; }
    .xgs-card { flex: 1 1 200px; min-width: 190px; border: 1px solid rgba(128, 128, 128, 0.25);
                border-inline-start: 4px solid #9e9e9e; border-radius: 3px; padding: 10px 14px;
                background-color: rgba(128, 128, 128, 0.04); }
    .xgs-card.ok { border-inline-start-color: #5cb85c; }
    .xgs-card.warn { border-inline-start-color: #f0ad4e; }
    .xgs-card.bad { border-inline-start-color: #d9534f; }
    .xgs-card .k { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; opacity: 0.6; }
    .xgs-card .v { font-size: 19px; font-weight: 600; line-height: 1.3; margin: 2px 0; }
    .xgs-card .s { font-size: 12px; opacity: 0.7; }
    .xgs-card .fa { opacity: 0.35; float: inline-end; font-size: 18px; margin-top: 2px; }
    .xgs-head { padding-top: 5px; padding-bottom: 5px; font-size: 16px; }
    /* KIT-CSS-END */
    /* A grid whose columns fill the width shows a one-pixel sideways bar when no vertical one takes
       the difference; wide screens never need to scroll it sideways. */
    @media (min-width: 768px) {
        #grid-map .tabulator-tableholder, #grid-users .tabulator-tableholder, #grid-groups .tabulator-tableholder,
        #grid-sources .tabulator-tableholder { overflow-x: hidden; }
    }
    .ui-note { padding: 0 15px 10px; }
    .ui-head { padding: 10px 15px 0; }
    .ui-foot { padding: 0 15px 15px; }
    /* NXLog's configuration is read as it is written, left to right, in either language */
    #ui-nxlog { direction: ltr; text-align: left; margin: 0 15px 10px; white-space: pre; overflow-x: auto; }
</style>

<script>
    $(document).ready(function () {
        /* KIT-JS-BEGIN */
        /* A string as OPNsense's API and Volt's lang._() hand it over - escaped - made plain for .text(). */
        function plain(value) {
            return $('<textarea/>').html(value === null || value === undefined ? '' : String(value)).text();
        }

        /* One card: cls '' (grey, no judgement), 'ok', 'warn' or 'bad'; icon a Font Awesome name. */
        function card(cls, icon, key, value, sub) {
            return $('<div class="xgs-card"/>').addClass(cls)
                .append($('<i class="fa"/>').addClass(icon))
                .append($('<div class="k"/>').text(plain(key)))
                .append($('<div class="v"/>').text(plain(value)))
                .append($('<div class="s"/>').text(plain(sub || ' ')));
        }

        /* Until the first reading: the same cards, their keys, and an ellipsis for every value. */
        function cards_wait(target, keys) {
            $(target).empty();
            $.each(keys, function (i, key) {
                $(target).append(card('', 'fa-ellipsis-h', key, '…', ''));
            });
        }

        /* The selected tab kept in the address, as on OPNsense's own tabbed pages. */
        function keep_tab() {
            if (window.location.hash !== '') {
                $('a[href="' + window.location.hash + '"]').tab('show');
            }
            $('.nav-tabs a').on('shown.bs.tab', function (e) {
                history.pushState(null, null, e.target.hash);
            });
        }
        /* KIT-JS-END */

        /* why a line or an event went no further, as events.py names it */
        const reasons = {
            'unreadable': "{{ lang._('not readable') }}",
            'failed': "{{ lang._('ticket not issued') }}",
            'no pre-authentication': "{{ lang._('ticket with no pre-authentication') }}",
            'computer': "{{ lang._('computer account') }}",
            'not a user': "{{ lang._('not a domain user') }}",
            'no address': "{{ lang._('no address') }}",
            'not a client address': "{{ lang._('not a client address') }}",
            'no time': "{{ lang._('no event time') }}",
            'not a domain controller': "{{ lang._('not a domain controller named') }}",
            'clock': "{{ lang._('ahead of the clock') }}",
            'firewall': "{{ lang._('an address of the firewall') }}",
            'domain controller': "{{ lang._('an address of a domain controller') }}",
            'never map': "{{ lang._('Never map') }}",
            'ignored': "{{ lang._('Ignore users') }}",
            'mac authentication': "{{ lang._('MAC authentication') }}",
            'voucher': "{{ lang._('a voucher') }}"
        };
        /* the sources beside the domain controllers say 'not a user' of a name that is nobody's */
        const nobody = "{{ lang._('names no user') }}";
        /* which source said it (engine.py's kinds) */
        const kinds = {
            'ad': "{{ lang._('Active Directory') }}",
            'radius': "{{ lang._('RADIUS') }}",
            'portal': "{{ lang._('Captive Portal') }}"
        };
        let counts = {};

        function count(n) {
            return n === null || n === undefined || n === '' ? '-' : Number(n).toLocaleString();
        }

        function when(ts) {
            return ts ? new Date(ts * 1000).toLocaleString() : '-';
        }

        /*
         * Four cards (the plan's): the users present, the group tables and the directory, the domain
         * controllers heard, and the last event with what was set aside.
         */
        function draw(data) {
            const $cards = $('#ui-cards').empty();
            if (!data || data.error) {
                $cards.append(card('bad', 'fa-id-badge', "{{ lang._('User Identity') }}", "{{ lang._('Status could not be read.') }}", ''));
                return;
            }
            counts = {};
            $.each(data.tables || [], function (i, t) {
                counts[t.alias] = t;
            });
            const c = data.counts || {};
            let state = '', sub = '';
            if (!data.enabled) {
                sub = "{{ lang._('off') }}";
            } else if (!data.running) {
                state = 'bad';
                sub = "{{ lang._('collector not running') }}";
            } else {
                state = c.clashes ? 'warn' : 'ok';
                sub = count(c.addresses) + ' ' + "{{ lang._('addresses') }}" + ' · ' + count(c.shared) + ' ' + "{{ lang._('shared') }}" +
                    (c.clashes ? ' · ' + count(c.clashes) + ' ' + "{{ lang._('clashes between sources') }}" : '');
            }
            $cards.append(card(state, 'fa-users', "{{ lang._('Users present') }}", data.enabled ? count(c.users) : "{{ lang._('off') }}", sub));

            const groups = (data.tables || []).filter(function (t) { return t.kind === 'group' && t.enabled; });
            const ldap = data.ldap || {};
            let lstate = '', lsub = "{{ lang._('no directory chosen') }}";
            if (ldap.chosen) {
                if (ldap.ok === false) {
                    lstate = 'warn';
                    lsub = "{{ lang._('the directory cannot be asked') }}" + (ldap.error ? ': ' + ldap.error : '');
                } else if (ldap.ok === true) {
                    lstate = groups.length ? 'ok' : '';
                    lsub = "{{ lang._('the directory answers') }}" + (ldap.chain === 'refused' ? ' · ' + "{{ lang._('nested groups refused') }}" : '');
                } else {
                    lsub = "{{ lang._('the directory not asked yet') }}";
                }
            }
            $cards.append(card(data.enabled ? lstate : '', 'fa-sitemap', "{{ lang._('Groups') }}", count(groups.length), lsub));

            /* the sources chosen and those heard: each domain controller named, RADIUS accounting, the
               captive portal - each heard once there is something to read */
            const named = (data.sources || []).filter(function (s) { return s.kind === 'ad' && s.named; });
            const heard = named.filter(function (s) { return s.last_line; });
            const source = data.source || {};
            const radius = data.radius || {}, portal = data.portal || {};
            let total = named.length, got = heard.length, parts = [], sstate = '';
            if (named.length) {
                parts.push(source.written ? "{{ lang._('receiving on port') }}" + ' ' + data.port :
                    "{{ lang._('not receiving') }}" + (source.reason ? ': ' + source.reason : ''));
            }
            if (radius.on) {
                total++;
                if (radius.found) {
                    got++;
                } else {
                    parts.push("{{ lang._('no RADIUS accounting to read') }}");
                }
            }
            if (portal.on) {
                total++;
                if (!portal.zones) {
                    parts.push("{{ lang._('no captive portal zone switched on') }}");
                } else if (portal.found && !portal.error) {
                    got++;
                } else {
                    parts.push(portal.error ? "{{ lang._('the portal\'s sessions cannot be read') }}" + ': ' + portal.error :
                        "{{ lang._('no captive portal session yet') }}");
                }
            }
            if (data.enabled) {
                if (!total) {
                    sstate = 'warn';
                    parts.push("{{ lang._('no source chosen') }}");
                } else if (named.length && !source.written) {
                    sstate = 'bad';
                } else {
                    sstate = got === total ? 'ok' : 'warn';
                }
            }
            $cards.append(card(sstate, 'fa-server', "{{ lang._('Sources heard') }}", got + ' / ' + total, parts.join(' · ')));

            let stale = 0, refused = 0;
            $.each(data.sources || [], function (i, s) {
                stale += s.stale || 0;
                refused += s.refused || 0;
            });
            $cards.append(card(stale || refused ? 'warn' : '', 'fa-clock-o', "{{ lang._('Last event') }}", when(data.last_event),
                count(stale) + ' ' + "{{ lang._('stale') }}" + ' · ' + count(refused) + ' ' + "{{ lang._('refused') }}"));

            $('#ui-off').toggle(!data.enabled);
            $('#ui-project').toggle(!!data.enabled && !!data.project);
            $('#ui-alone').toggle(!!data.enabled && !data.project);
            $('#ui-source').text(plain("{{ lang._('Not receiving: syslog-ng\'s source is not written.') }}" +
                (source.reason ? ' ' + source.reason : ''))).toggle(!!data.enabled && named.length > 0 && !source.written);
            nxlog(data);
        }

        /* NXLog CE's configuration for a domain controller (settled point 2), as phase 0's lab ran it:
           the two events that map, as JSON over TCP, to the first chosen interface's address - with each
           event's time sent as seconds since 1970 (integer() gives NXLog's own count, microseconds in
           UTC), so a domain controller in another time zone is read right, and without the event's long
           text (delete($Message)), which nothing here reads and which made half of each line. Not
           DateFormat: NXLog CE 3.2 refuses it and does not start ("Invalid keyword: DateFormat", phase
           1's lab); integer() it runs, and with the domain controller four hours ahead of UTC the
           number it sent was still UTC's. */
        function nxlog(data) {
            const first = (data.listen || []).filter(function (l) { return l.address; })[0];
            const host = first ? first.address : "{{ lang._('the address of the firewall on the chosen interface') }}";
            $('#ui-nxlog').text([
                '<Extension json>',
                '    Module  xm_json',
                '</Extension>',
                '<Input security>',
                '    Module  im_msvistalog',
                '    <QueryXML>',
                '        <QueryList><Query Id="0"><Select Path="Security">*[System[(EventID=4768 or EventID=4624)]]</Select></Query></QueryList>',
                '    </QueryXML>',
                '    Exec    delete($Message); $EventTime = integer($EventTime) / 1000000; to_json();',
                '</Input>',
                '<Output firewall>',
                '    Module  om_tcp',
                '    Host    ' + host,
                '    Port    ' + (data.port || 514),
                '</Output>',
                '<Route r>',
                '    Path    security => firewall',
                '</Route>'
            ].join('\n'));
        }

        function refresh() {
            ajaxGet('/api/useridentity/service/status', {}, function (data) {
                draw(data);
                $('#grid-groups').bootgrid('reload');
                $('#grid-users').bootgrid('reload');
            });
        }

        /* the table of a group or user row: its alias, and the addresses pf holds there */
        function tableCell(column, row) {
            const t = counts[row.alias];
            let out = '<code>' + row.alias + '</code>';
            if (!t || !t.present) {
                return out + ' <span class="text-muted">' + (t && t.owner ? "{{ lang._('an alias of the owner\'s has this name') }}" :
                    "{{ lang._('not applied yet') }}") + '</span>';
            }
            if (t.cut) {
                out += ' <i class="fa fa-scissors text-muted" title="' + "{{ lang._('XGS: Settings cuts the open connections of an address that joins it') }}" + '"></i>';
            }
            return out;
        }

        function entriesCell(column, row) {
            const t = counts[row.alias];
            return t && t.present ? count(t.entries) : '-';
        }

        /* a source as the Users and Sources tabs name it: its kind, then who - the domain controller or
           the RADIUS client, or the portal's zone by its description */
        function sourceName(kind, source, name) {
            if (kind === 'portal') {
                return (kinds.portal) + ' · ' + (name || ("{{ lang._('Zone') }}" + ' ' + source));
            }
            return (kinds[kind] || kind) + (source ? ' · <code>' + source + '</code>' : '');
        }

        /* The grids' rows are built by the API controllers; the API escapes what it returns, so
           nothing here escapes it again. */
        $('#grid-map').UIBootgrid({
            search: '/api/useridentity/service/search_map',
            options: {
                selection: false,
                formatters: {
                    time: function (column, row) {
                        return when(row[column.id]);
                    },
                    mono: function (column, row) {
                        return row[column.id] ? '<code>' + row[column.id] + '</code>' : '-';
                    },
                    groups: function (column, row) {
                        if (!row.known) {
                            return '<span class="text-muted">' + "{{ lang._('not known yet') }}" + '</span>';
                        }
                        return row.groups || '-';
                    },
                    source: function (column, row) {
                        return sourceName(row.kind, row.source, row.source_name);
                    },
                    /* the other users within the lifetime: shared with them, or - one of them from
                       another source - a clash between the sources, each named */
                    shared: function (column, row) {
                        if (row.clash) {
                            return '<span class="text-danger">' + "{{ lang._('clash with') }}" + ' ' +
                                $.map(row.others || [], function (o) {
                                    return o.user + ' (' + (kinds[o.kind] || o.kind) + ')';
                                }).join(', ') + '</span>';
                        }
                        return row.shared ? '<span class="text-warning">' + "{{ lang._('shared with') }}" + ' ' + row.shared + '</span>' : '-';
                    }
                }
            }
        });

        $('#grid-users').UIBootgrid({
            search: '/api/useridentity/settings/search_users',
            get: '/api/useridentity/settings/get_user/',
            set: '/api/useridentity/settings/set_user/',
            add: '/api/useridentity/settings/add_user/',
            del: '/api/useridentity/settings/del_user/',
            toggle: '/api/useridentity/settings/toggle_user/',
            options: {
                formatters: {
                    table: tableCell,
                    entries: entriesCell
                }
            }
        });

        $('#grid-groups').UIBootgrid({
            search: '/api/useridentity/settings/search_groups',
            get: '/api/useridentity/settings/get_group/',
            set: '/api/useridentity/settings/set_group/',
            add: '/api/useridentity/settings/add_group/',
            del: '/api/useridentity/settings/del_group/',
            toggle: '/api/useridentity/settings/toggle_group/',
            options: {
                formatters: {
                    table: tableCell,
                    entries: entriesCell
                }
            }
        });

        $('#grid-sources').UIBootgrid({
            search: '/api/useridentity/service/search_sources',
            options: {
                selection: false,
                formatters: {
                    kind: function (column, row) {
                        return kinds[row.kind] || row.kind;
                    },
                    sender: function (column, row) {
                        if (row.kind === 'portal') {
                            return "{{ lang._('Zone') }}" + ' ' + row.address;
                        }
                        return '<span dir="ltr">' + row.address + '</span>' + (row.named ? '' :
                            ' <span class="text-warning">' + "{{ lang._('not named') }}" + '</span>');
                    },
                    time: function (column, row) {
                        return when(row[column.id]);
                    },
                    late: function (column, row) {
                        return row.late === null || row.late === undefined ? '-' : Number(row.late).toLocaleString() + ' s';
                    },
                    number: function (column, row) {
                        return count(row[column.id]);
                    },
                    reasons: function (column, row) {
                        const parts = $.map(row.reasons || [], function (r) {
                            const said = row.kind !== 'ad' && r.reason === 'not a user' ? nobody : reasons[r.reason];
                            return (said || r.reason) + ' ' + count(r.count);
                        });
                        return parts.length ? parts.join(' · ') : '-';
                    }
                }
            }
        });

        /* the cards, and the grids of the tab on screen */
        $('#refreshAct').click(function () {
            refresh();
            const tab = $('#maintabs li.active a').attr('href');
            if (tab === '#users') {
                $('#grid-map').bootgrid('reload');
            } else if (tab === '#sources') {
                $('#grid-sources').bootgrid('reload');
            }
        });

        /* Apply: the aliases, syslog-ng's source, the filter, the collector (reconfigure) */
        function apply($button, $progress, $result, save) {
            $button.prop('disabled', true);
            $progress.addClass('fa fa-spinner fa-pulse');
            const done = function () {
                $progress.removeClass('fa fa-spinner fa-pulse');
                $button.prop('disabled', false);
            };
            const go = function () {
                ajaxCall('/api/useridentity/service/reconfigure', {}, function (data) {
                    done();
                    let lines = (data && data.changes ? data.changes : []).concat(data && data.notes ? data.notes : [])
                        .concat(data && data.errors ? data.errors : []);
                    const source = data && data.source ? data.source : null;
                    if (source && !source.written && data.enabled) {
                        lines.push("{{ lang._('Not receiving: syslog-ng\'s source is not written.') }}" + (source.reason ? ' ' + source.reason : ''));
                    }
                    $result.attr('class', data && data.status === 'ok' ? 'text-muted' : 'alert alert-danger')
                        .text(plain(lines.length ? lines.join(' · ') : "{{ lang._('Nothing to change in aliases.') }}")).show();
                    refresh();
                    $('#grid-map').bootgrid('reload');
                    $('#grid-sources').bootgrid('reload');
                });
            };
            if (save) {
                saveFormToEndpoint('/api/useridentity/settings/set', 'frm_general', go, false, done);
            } else {
                go();
            }
        }

        mapDataToFormUI({'frm_general': '/api/useridentity/settings/get'}).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });
        $('#applyAct').click(function () {
            apply($(this), $('#frm_general_progress'), $('#ui-result'), true);
        });
        $('#applyGroupsAct').click(function () {
            apply($(this), $('#ui-groups-progress'), $('#ui-groups-result'), false);
        });
        $('#applyUsersAct').click(function () {
            apply($(this), $('#ui-users-progress'), $('#ui-users-result'), false);
        });

        /* Users: every mapping forgotten */
        $('#flushAct').click(function () {
            const $button = $(this);
            BootstrapDialog.confirm({
                title: "{{ lang._('Forget every mapping') }}",
                message: "{{ lang._('Every address is taken out of the map and of the tables now. The next logon or network logon of each user maps it again; a captive portal session still open within half a minute, a RADIUS session at its next Interim-Update.') }}",
                type: BootstrapDialog.TYPE_WARNING,
                btnOKLabel: "{{ lang._('Forget') }}",
                callback: function (yes) {
                    if (!yes) {
                        return;
                    }
                    $button.prop('disabled', true);
                    ajaxCall('/api/useridentity/service/flush', {}, function () {
                        $button.prop('disabled', false);
                        refresh();
                        $('#grid-map').bootgrid('reload');
                    });
                }
            });
        });

        /* Groups: one user asked of the directory */
        const members = {
            'direct': "{{ lang._('in it') }}",
            'nested': "{{ lang._('in it, through a group inside it') }}",
            'no': "{{ lang._('not in it') }}",
            'no group': "{{ lang._('no such group') }}",
            'off': "{{ lang._('row switched off') }}"
        };
        $('#testAct').click(function () {
            const $button = $(this).prop('disabled', true);
            $('#ui-test-result').attr('class', 'text-muted').text('…').show();
            ajaxCall('/api/useridentity/service/ldaptest', {'user': $('#ui-test-user').val()}, function (data) {
                $button.prop('disabled', false);
                if (!data || data.status !== 'ok') {
                    $('#ui-test-result').attr('class', 'alert alert-danger').text(plain(data && data.error ? data.error :
                        "{{ lang._('No answer could be read.') }}"));
                    return;
                }
                const parts = [data.found ? data.dn : "{{ lang._('the directory does not hold this user') }}"];
                $.each(data.groups || [], function (i, g) {
                    parts.push(g.group + ': ' + (members[g.member] || g.member));
                });
                parts.push(count(data.took_ms) + ' ms');
                $('#ui-test-result').attr('class', 'text-muted').text(plain(parts.join(' · ')));
            });
        });

        cards_wait('#ui-cards', ["{{ lang._('Users present') }}", "{{ lang._('Groups') }}", "{{ lang._('Sources heard') }}",
            "{{ lang._('Last event') }}"]);
        refresh();
        keep_tab();
    });
</script>

<div class="xgs-cards xgs-top" id="ui-cards"></div>
<div class="text-muted clearfix" style="padding: 0 0 10px;">
    <button id="refreshAct" class="btn btn-default btn-xs pull-right" type="button" title="{{ lang._('Refresh') }}"><i class="fa fa-fw fa-refresh"></i></button>
    <span id="ui-off" style="display: none;">{{ lang._('User Identity is off: no address is mapped.') }}</span>
    <span id="ui-project" style="display: none;">{{ lang._('os-xgs-npu is installed: when an address joins one of these tables, XGS: Settings cuts the connections it already has open within a minute, in hardware first, so the rules that name the table apply to all of them. Leaving a table cuts nothing.') }}</span>
    <span id="ui-alone" style="display: none;">{{ lang._('Without os-xgs-npu no open connection is cut: an address that joins a table keeps the connections it had, and the rules that name the table apply to its new ones.') }}</span>
    <span id="ui-source" class="text-warning" style="display: none;"></span>
</div>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#users">{{ lang._('Users') }}</a></li>
    <li><a data-toggle="tab" href="#groups">{{ lang._('Groups') }}</a></li>
    <li><a data-toggle="tab" href="#sources">{{ lang._('Sources') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="users" class="tab-pane active">
        <table id="grid-map" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="address" data-formatter="mono" data-type="string" data-identifier="true">{{ lang._('Address') }}</th>
                    <th data-column-id="user" data-type="string">{{ lang._('User') }}</th>
                    <th data-column-id="groups" data-formatter="groups" data-type="string">{{ lang._('Groups') }}</th>
                    <th data-column-id="source" data-formatter="source" data-type="string">{{ lang._('Source') }}</th>
                    <th data-column-id="first" data-formatter="time" data-type="numeric">{{ lang._('Since') }}</th>
                    <th data-column-id="last" data-formatter="time" data-type="numeric">{{ lang._('Last event') }}</th>
                    <th data-column-id="expires" data-formatter="time" data-type="numeric">{{ lang._('Until') }}</th>
                    <th data-column-id="mac" data-formatter="mono" data-type="string" data-visible="false">{{ lang._('MAC') }}</th>
                    <th data-column-id="shared" data-formatter="shared" data-type="string">{{ lang._('Shared') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot></tfoot>
        </table>
        <div class="text-muted ui-note clearfix">
            <button id="flushAct" class="btn btn-default btn-xs pull-right" type="button">{{ lang._('Forget every mapping') }}</button>
            {{ lang._('Each address with the user a source last saw on it: a domain controller, RADIUS accounting or the captive portal. The latest wins: an address another user was seen on within the lifetime is shown as shared - a terminal server, or a runas on a client while someone sits at its screen - and as a clash when two sources gave it to two users. A RADIUS Stop and the end of a portal session end a mapping at once; a domain controller says nothing at a logoff: its mappings end at the end of their lifetime, when another device takes the address, or when forgotten here.') }}
        </div>
        <div class="xgs-head ui-head">{{ lang._('A table for a user') }}</div>
        <table id="grid-users" class="table table-condensed table-hover table-striped" data-editDialog="DialogUser">
            <thead>
                <tr>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="enabled" data-width="6em" data-type="boolean" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                    <th data-column-id="name" data-type="string">{{ lang._('User') }}</th>
                    <th data-column-id="alias" data-type="string" data-formatter="table">{{ lang._('Alias') }}</th>
                    <th data-column-id="entries" data-type="numeric" data-formatter="entries" data-sortable="false" data-width="8em">{{ lang._('Addresses') }}</th>
                    <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                    <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot>
                <tr>
                    <td></td>
                    <td>
                        <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-plus fa-fw"></span></button>
                        <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-trash-o fa-fw"></span></button>
                    </td>
                </tr>
            </tfoot>
        </table>
        <div class="ui-foot">
            <button id="applyUsersAct" class="btn btn-primary" type="button"><b>{{ lang._('Apply') }}</b> <i id="ui-users-progress"></i></button>
            <div id="ui-users-result" style="display: none; padding-top: 10px;"></div>
        </div>
    </div>
    <div id="groups" class="tab-pane">
        <table id="grid-groups" class="table table-condensed table-hover table-striped" data-editDialog="DialogGroup">
            <thead>
                <tr>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="enabled" data-width="6em" data-type="boolean" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                    <th data-column-id="name" data-type="string">{{ lang._('Group') }}</th>
                    <th data-column-id="alias" data-type="string" data-formatter="table">{{ lang._('Alias') }}</th>
                    <th data-column-id="entries" data-type="numeric" data-formatter="entries" data-sortable="false" data-width="8em">{{ lang._('Addresses') }}</th>
                    <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                    <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot>
                <tr>
                    <td></td>
                    <td>
                        <button data-action="add" type="button" class="btn btn-xs btn-primary"><span class="fa fa-plus fa-fw"></span></button>
                        <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default"><span class="fa fa-trash-o fa-fw"></span></button>
                    </td>
                </tr>
            </tfoot>
        </table>
        <div class="text-muted ui-note">
            {{ lang._('A table for each group: the addresses of its users, asked of the directory chosen in Settings when a user is first seen and again after 15 minutes. Each is an External alias in Firewall: Aliases, for a rule\'s source or destination. Changes here take effect with Apply.') }}
        </div>
        <div class="ui-foot">
            <button id="applyGroupsAct" class="btn btn-primary" type="button"><b>{{ lang._('Apply') }}</b> <i id="ui-groups-progress"></i></button>
            <div id="ui-groups-result" style="display: none; padding-top: 10px;"></div>
        </div>
        <div class="xgs-head ui-head">{{ lang._('Ask the directory about a user') }}</div>
        <div class="ui-foot form-inline">
            <input id="ui-test-user" type="text" class="form-control" placeholder="{{ lang._('User') }}" dir="ltr"/>
            <button id="testAct" class="btn btn-default" type="button">{{ lang._('Test') }}</button>
            <div id="ui-test-result" style="display: none; padding-top: 10px;"></div>
        </div>
    </div>
    <div id="sources" class="tab-pane">
        <table id="grid-sources" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="order" data-type="numeric" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="kind" data-formatter="kind" data-type="string">{{ lang._('Source') }}</th>
                    <th data-column-id="address" data-formatter="sender" data-type="string">{{ lang._('Sender') }}</th>
                    <th data-column-id="hostname" data-type="string">{{ lang._('Name') }}</th>
                    <th data-column-id="last_line" data-formatter="time" data-type="numeric">{{ lang._('Last heard') }}</th>
                    <th data-column-id="last_event" data-formatter="time" data-type="numeric">{{ lang._('Last event') }}</th>
                    <th data-column-id="late" data-formatter="late" data-type="numeric" data-width="7em">{{ lang._('Late') }}</th>
                    <th data-column-id="accepted" data-formatter="number" data-type="numeric" data-width="7em">{{ lang._('Taken') }}</th>
                    <th data-column-id="joined" data-formatter="number" data-type="numeric" data-width="7em">{{ lang._('Mapped') }}</th>
                    <th data-column-id="renewed" data-formatter="number" data-type="numeric" data-width="7em">{{ lang._('Renewed') }}</th>
                    <th data-column-id="ended" data-formatter="number" data-type="numeric" data-width="7em">{{ lang._('Ended') }}</th>
                    <th data-column-id="stale" data-formatter="number" data-type="numeric" data-width="7em">{{ lang._('Stale') }}</th>
                    <th data-column-id="reasons" data-formatter="reasons" data-type="string" data-sortable="false">{{ lang._('Refused') }}</th>
                    <th data-column-id="other" data-formatter="number" data-type="numeric" data-width="7em">{{ lang._('Other events') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot></tfoot>
        </table>
        <div class="text-muted ui-note">
            {{ lang._('Since the collector started: the lines each sender sent, the events taken - a ticket issued (4768) or a logon to the domain controller with an address (4624) - those that mapped an address or renewed one, those older than Stale after when they came, those refused and why, and the other events counted and set aside. Late: how long after it happened the last event came. Lines are counted, never kept.') }}
        </div>
        <div class="text-muted ui-note">
            {{ lang._('RADIUS: each client of os-freeradius whose accounting was read - its records, the addresses a Start or an Interim-Update mapped or renewed, those a Stop ended, those older than the mapping lifetime when read (stale), those refused and why; Accounting-On and Accounting-Off, which end every session of their NAS, among the others. Captive Portal: each zone switched on - the sessions it held, the addresses they mapped and those their end took out, and those refused and why.') }}
        </div>
        <div class="xgs-head ui-head">{{ lang._('NXLog CE on each domain controller') }}</div>
        <div class="text-muted ui-note">
            {{ lang._('NXLog Community Edition reads the Security log and sends the two events as JSON over TCP. Its configuration, as phase 0\'s lab ran it, to put in nxlog.conf on each domain controller named in Settings, then restart its service:') }}
        </div>
        <pre id="ui-nxlog"></pre>
        <div class="text-muted ui-note">
            {{ lang._('integer($EventTime) / 1000000 makes NXLog CE send the time of each event as seconds since 1970, in UTC, so the firewall reads it right whatever the time zone of the domain controller; without it the time is read in the zone of the firewall. delete($Message) leaves out the long text of each event, which nothing here reads, and keeps each line well under what one datagram to the collector can carry.') }}
        </div>
        <div class="text-muted ui-note">
            {{ lang._('The domain controllers keep their audit of Kerberos Authentication Service and of Logon for success, as Windows Server does by default. TLS from the domain controllers is not taken yet: the redirect, from their addresses alone, is what lets a line in.') }}
        </div>
    </div>
    <div id="settings" class="tab-pane">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general', 'apply_btn_id': 'applyAct']) }}
        <div style="padding: 0 15px 15px;"><div id="ui-result" style="display: none;"></div></div>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': formDialogGroup, 'id': 'DialogGroup', 'label': lang._('Edit group')]) }}
{{ partial("layout_partials/base_dialog", ['fields': formDialogUser, 'id': 'DialogUser', 'label': lang._('Edit user')]) }}
{{ partial("OPNsense/UserIdentity/credit") }}
