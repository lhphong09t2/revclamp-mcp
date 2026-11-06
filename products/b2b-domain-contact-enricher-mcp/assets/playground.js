(() => {
  'use strict';

  function isSafeExternalHttpsUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl.trim()) return false;
    try {
      const parsed = new URL(rawUrl);
      return parsed.protocol === 'https:';
    } catch {
      return false;
    }
  }

  function clearChildren(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function createEl(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined && text !== null) {
      el.textContent = String(text);
    }
    return el;
  }

  const state = {
    tools: [],
    selectedToolName: 'resolve_b2b_domain_contacts',
    lastNextPageToken: null,
    loadPreviewsOptIn: false,
    lastResultPayload: null,
    rpcRequestId: 1,
    activeRequestToken: 0,
  };

  const TOOL_UI_META = {
    resolve_b2b_domain_contacts: {
      title: 'Resolve B2B Domain Contacts, Security.txt & DNS Posture',
      fields: {
        query: {
          title: 'Target B2B Domain or Comma-Separated Domains',
          placeholder: 'e.g. stripe.com, cloudflare.com, linear.app',
          hint: 'Enter one or more B2B domains or HTTPS URLs to enrich with RFC 9116 security.txt, Schema.org ContactPoint, and DNS posture.',
        },
        roleFilter: {
          title: 'Contact Role Filter (Optional)',
          hint: 'Filter extracted contacts by functional department role (ANY, SECURITY, PRIVACY_DPO, BILLING_FINANCE, LEGAL, SUPPORT, SALES, PRESS, GENERAL).',
        },
        includeDnsPosture: {
          title: 'Include DNS MX / SPF / DMARC Posture',
          hint: 'Resolve live MX gateway provider, SPF policy, and DMARC enforcement posture via DNS-over-HTTPS.',
        },
        includeSecurityTxt: {
          title: 'Include RFC 9116 /.well-known/security.txt',
          hint: 'Inspect RFC 9116 security disclosure contacts, PGP encryption keys, and policy URLs.',
        },
        limit: {
          title: 'Max Domain Profiles per Call',
          placeholder: '1 to 25',
          hint: 'Maximum number of enriched domain contact profiles returned in a single call (1 to 25).',
        },
        pageToken: {
          title: 'Pagination Cursor Token (Optional)',
          placeholder: 'Paste rcd1_... cursor from a previous run',
          hint: 'Opaque deterministic pagination cursor to fetch the next domain slice.',
        },
      },
    },
    inspect_domain_dns_and_security_txt: {
      title: 'Inspect Domain RFC 9116 Security.txt & DNS Posture',
      fields: {
        domain: {
          title: 'Target B2B Domain or URL',
          placeholder: 'e.g. stripe.com',
          hint: 'Domain to inspect for RFC 9116 security.txt directives and MX/SPF/DMARC DNS posture.',
        },
      },
    },
    verify_email_deliverability_posture: {
      title: 'Verify B2B Email Deliverability & Role Posture',
      fields: {
        email: {
          title: 'B2B Email Address to Verify',
          placeholder: 'e.g. security@stripe.com',
          hint: 'B2B email address to classify by role and verify against live domain MX, SPF, and DMARC DNS posture.',
        },
      },
    },
  };

  const els = {
    toolSelect: document.getElementById('tool-select'),
    dynamicFields: document.getElementById('dynamic-schema-fields'),
    loadPreviewsCheckbox: document.getElementById('toggle-load-previews'),
    runBtn: document.getElementById('btn-run-tool'),
    nextPageBtn: document.getElementById('btn-load-next-page'),
    copyJsonBtn: document.getElementById('btn-copy-json'),
    downloadJsonBtn: document.getElementById('btn-download-json'),
    statusBanner: document.getElementById('status-banner'),
    billingModeValue: document.getElementById('telemetry-billing-mode'),
    extractedCountValue: document.getElementById('telemetry-extracted-count'),
    paginationStatusValue: document.getElementById('telemetry-pagination-status'),
    envelopeBytesValue: document.getElementById('telemetry-envelope-bytes'),
    cardsContainer: document.getElementById('results-cards-container'),
    rawJsonBox: document.getElementById('raw-json-output'),
  };

  function setExportButtonsEnabled(enabled) {
    const isEnabled = Boolean(enabled);
    if (els.copyJsonBtn) els.copyJsonBtn.disabled = !isEnabled;
    if (els.downloadJsonBtn) els.downloadJsonBtn.disabled = !isEnabled;
  }

  function clearExportableResultState(clearCards = false, resetTelemetry = false) {
    state.lastResultPayload = null;
    setExportButtonsEnabled(false);
    if (clearCards && els.cardsContainer) {
      clearChildren(els.cardsContainer);
    }
    if (resetTelemetry) {
      if (els.billingModeValue) els.billingModeValue.textContent = 'Local mode - not billed';
      if (els.extractedCountValue) els.extractedCountValue.textContent = '0';
      if (els.paginationStatusValue) els.paginationStatusValue.textContent = 'IDLE';
      if (els.envelopeBytesValue) els.envelopeBytesValue.textContent = '0 B';
    }
  }

  function humanizeRpcErrorMessage(rpcError) {
    const code = Number(rpcError?.code);
    const rawMsg = String(rpcError?.message || 'Request failed');
    const cleanMsg = rawMsg
      .replace(/^Invalid params:\s*/i, '')
      .replace(/\broleFilter\b/g, 'Contact Role Filter')
      .replace(/\bpageToken\b/g, 'Pagination Cursor Token');
    if (code === -32602) {
      return `Invalid input: ${cleanMsg}`;
    }
    if (code === -32601) {
      return `Unsupported action: ${cleanMsg}`;
    }
    return `Request error (${code || 'RPC'}): ${cleanMsg}`;
  }

  function getHumanToolTitle(toolName) {
    return (
      TOOL_UI_META[toolName]?.title ||
      state.tools.find((t) => t.name === toolName)?.title ||
      toolName
    );
  }

  function getSelectedToolSchema() {
    return (
      state.tools.find((t) => t.name === state.selectedToolName) ||
      state.tools[0] ||
      null
    );
  }

  function resetStalePaginationCursorOnFilterEdit(changedFieldName) {
    if (changedFieldName === 'pageToken') return;
    state.activeRequestToken += 1;
    if (els.statusBanner && els.statusBanner.dataset.state === 'pending') {
      els.statusBanner.dataset.state = 'idle';
      els.statusBanner.textContent = 'Ready - filter updated; click Run to execute.';
    }
    const pageTokenInput = document.getElementById('field-pageToken');
    if (pageTokenInput && pageTokenInput.value) {
      pageTokenInput.value = '';
    }
    state.lastNextPageToken = null;
    if (els.nextPageBtn) {
      els.nextPageBtn.hidden = true;
    }
  }

  function renderSchemaFields() {
    clearChildren(els.dynamicFields);
    const tool = getSelectedToolSchema();
    if (!tool || !tool.inputSchema || !tool.inputSchema.properties) {
      return;
    }

    const props = tool.inputSchema.properties;
    const defaultValues = {
      query: 'stripe.com',
      domain: 'stripe.com',
      email: 'security@stripe.com',
      roleFilter: 'ANY',
      limit: '5',
    };

    for (const [fieldName, fieldSpec] of Object.entries(props)) {
      if (fieldName === 'domains' || fieldName === 'maxResults') {
        continue;
      }

      const uiFieldMeta = TOOL_UI_META[state.selectedToolName]?.fields?.[fieldName] || {};
      const fieldTitle = uiFieldMeta.title || fieldSpec.title || fieldName;
      const fieldHint = uiFieldMeta.hint || fieldSpec.description || '';
      const fieldPlaceholder = uiFieldMeta.placeholder || fieldTitle;

      const group = createEl('div', 'field-group');
      const inputId = `field-${fieldName}`;

      if (fieldSpec.type === 'boolean') {
        const label = createEl('label', 'checkbox-row');
        label.setAttribute('for', inputId);
        const checkbox = createEl('input', 'checkbox-input');
        checkbox.id = inputId;
        checkbox.name = fieldName;
        checkbox.type = 'checkbox';
        checkbox.checked = fieldSpec.default !== false;
        checkbox.addEventListener('change', () => {
          resetStalePaginationCursorOnFilterEdit(fieldName);
        });
        label.appendChild(checkbox);
        label.appendChild(createEl('span', '', fieldTitle));
        group.appendChild(label);
      } else {
        const label = createEl('label', 'field-label', fieldTitle);
        label.setAttribute('for', inputId);
        group.appendChild(label);

        if (Array.isArray(fieldSpec.enum) && fieldSpec.enum.length > 0) {
          const select = createEl('select', 'select-control');
          select.id = inputId;
          select.name = fieldName;
          for (const optionVal of fieldSpec.enum) {
            const opt = createEl('option', '', optionVal);
            opt.value = optionVal;
            if (defaultValues[fieldName] === optionVal || fieldSpec.default === optionVal) {
              opt.selected = true;
            }
            select.appendChild(opt);
          }
          select.addEventListener('change', () => {
            resetStalePaginationCursorOnFilterEdit(fieldName);
          });
          group.appendChild(select);
        } else {
          const input = createEl('input', 'input-control');
          input.id = inputId;
          input.name = fieldName;
          input.type = fieldSpec.type === 'integer' ? 'number' : 'text';
          if (fieldSpec.minimum !== undefined) input.min = String(fieldSpec.minimum);
          if (fieldSpec.maximum !== undefined) input.max = String(fieldSpec.maximum);
          if (fieldSpec.maxLength !== undefined) input.maxLength = Number(fieldSpec.maxLength);
          if (defaultValues[fieldName] !== undefined) {
            input.value = String(defaultValues[fieldName]);
          }
          input.placeholder = fieldPlaceholder;
          input.addEventListener('input', () => {
            resetStalePaginationCursorOnFilterEdit(fieldName);
          });
          group.appendChild(input);
        }
      }

      if (fieldHint) {
        const hint = createEl('div', 'field-hint', fieldHint);
        group.appendChild(hint);
      }

      els.dynamicFields.appendChild(group);
    }
  }

  function collectToolArguments() {
    const tool = getSelectedToolSchema();
    if (!tool || !tool.inputSchema || !tool.inputSchema.properties) {
      return {};
    }
    const args = {};
    for (const [fieldName, fieldSpec] of Object.entries(tool.inputSchema.properties)) {
      const el = document.getElementById(`field-${fieldName}`);
      if (!el) continue;
      if (fieldSpec.type === 'boolean') {
        args[fieldName] = Boolean(el.checked);
      } else if (fieldSpec.type === 'integer') {
        const raw = el.value.trim();
        if (raw !== '') {
          args[fieldName] = Number(raw);
        }
      } else {
        const raw = el.value.trim();
        if (raw !== '') {
          args[fieldName] = raw;
        }
      }
    }
    return args;
  }

  function renderDomainProfileCard(item) {
    const card = createEl('article', 'job-card');
    const header = createEl('div', 'job-card-header');
    const title = createEl(
      'div',
      'job-title',
      `${item.organizationName || item.domain} (${item.domain})`
    );
    const badgesWrap = createEl('div', 'job-tech-row');
    const posture = item.dnsDeliverability || {};
    badgesWrap.appendChild(
      createEl(
        'span',
        'badge badge-emerald',
        `Readiness: ${posture.deliverabilityReadinessScore ?? 0}/100 (${posture.grade || 'N/A'})`
      )
    );
    badgesWrap.appendChild(
      createEl('span', 'badge badge-cyan', `Gateway: ${posture.emailGatewayProvider || 'NONE'}`)
    );
    header.appendChild(title);
    header.appendChild(badgesWrap);
    card.appendChild(header);

    const secTxt = item.securityTxt || {};
    const meta = createEl(
      'div',
      'job-meta',
      `ID: ${item.profileId} | Contacts: ${item.contactCount ?? 0} | SPF: ${posture.spfPolicy || 'MISSING'} | DMARC: ${posture.dmarcPolicy || 'MISSING'} | RFC 9116 security.txt: ${secTxt.found ? 'FOUND' : 'NOT_FOUND'}`
    );
    card.appendChild(meta);

    if (Array.isArray(item.contacts) && item.contacts.length > 0) {
      const contactsRow = createEl('div', 'job-tech-row');
      for (const c of item.contacts) {
        const label = c.email
          ? `${c.role}: ${c.email} (${c.confidenceScore}%)`
          : `${c.role}: ${c.contactUri || c.telephone || 'URI'}`;
        contactsRow.appendChild(createEl('span', 'badge', label));
      }
      card.appendChild(contactsRow);
    }

    if (item.untrustedDomainExcerpt && item.untrustedDomainExcerpt.plainTextExcerpt) {
      const excerptBox = createEl('div', 'job-excerpt-box');
      const excerptHeader = createEl('div', 'job-excerpt-header');
      excerptHeader.appendChild(
        createEl('span', 'badge badge-amber', 'Untrusted Public Domain Signal - Data Only')
      );
      excerptBox.appendChild(excerptHeader);
      excerptBox.appendChild(
        createEl('div', 'job-excerpt-body', item.untrustedDomainExcerpt.plainTextExcerpt)
      );
      card.appendChild(excerptBox);
    }

    const policyUrl = secTxt.policyUrls?.[0] || item.canonicalWebsiteUrl;
    if (state.loadPreviewsOptIn && isSafeExternalHttpsUrl(policyUrl)) {
      const linksRow = createEl('div', 'job-links');
      const link = createEl('a', 'btn btn-secondary', 'Open Verified Domain / Policy URL');
      link.href = policyUrl;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      linksRow.appendChild(link);
      card.appendChild(linksRow);
    }

    return card;
  }

  function renderResultCards(structured) {
    clearChildren(els.cardsContainer);
    if (!structured || typeof structured !== 'object') {
      els.cardsContainer.appendChild(
        createEl('div', 'field-hint', 'No structured records to display.')
      );
      return;
    }

    const items = Array.isArray(structured.items) ? structured.items : [];
    if (items.length > 0) {
      for (const item of items) {
        els.cardsContainer.appendChild(renderDomainProfileCard(item));
      }
      return;
    }

    if (structured.domainProfile && typeof structured.domainProfile === 'object') {
      els.cardsContainer.appendChild(renderDomainProfileCard(structured.domainProfile));
      return;
    }

    if (structured.email && structured.domain) {
      const card = createEl('article', 'job-card');
      const header = createEl('div', 'job-card-header');
      header.appendChild(
        createEl('div', 'job-title', `${structured.email} (${structured.role || 'GENERAL'})`)
      );
      header.appendChild(
        createEl(
          'span',
          'badge badge-emerald',
          `${structured.deliverabilityVerdict || 'CHECKED'} (${structured.confidenceScore ?? 0}%)`
        )
      );
      card.appendChild(header);
      const posture = structured.dnsDeliverability || {};
      card.appendChild(
        createEl(
          'div',
          'job-meta',
          `Domain: ${structured.domain} | Role Email: ${structured.isRoleAccount ? 'YES' : 'NO'} | Gateway: ${posture.emailGatewayProvider || 'NONE'} | SPF: ${posture.spfPolicy || 'MISSING'} | DMARC: ${posture.dmarcPolicy || 'MISSING'}`
        )
      );
      els.cardsContainer.appendChild(card);
      return;
    }

    els.cardsContainer.appendChild(
      createEl(
        'div',
        'field-hint',
        `Status: ${structured.status || 'EMPTY_RESULT'} (0 domain profiles matched)`
      )
    );
  }

  async function copyExportableJson() {
    if (!state.lastResultPayload || typeof state.lastResultPayload !== 'object') {
      return;
    }
    const tokenAtCopyStart = state.activeRequestToken;
    const serialized = JSON.stringify(state.lastResultPayload, null, 2);
    let copied = false;
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        await navigator.clipboard.writeText(serialized);
        copied = true;
      }
    } catch {
      copied = false;
    }
    if (tokenAtCopyStart !== state.activeRequestToken) return;
    if (copied) {
      els.statusBanner.dataset.state = 'ok';
      els.statusBanner.textContent = `Copied structured JSON (${serialized.length} chars) to clipboard.`;
    } else {
      els.statusBanner.dataset.state = 'warn';
      els.statusBanner.textContent = `Clipboard copy unavailable (${serialized.length} chars) - use Download JSON or copy from the box below.`;
    }
  }

  function downloadExportableJson() {
    if (!state.lastResultPayload || typeof state.lastResultPayload !== 'object') {
      return;
    }
    const serialized = JSON.stringify(state.lastResultPayload, null, 2);
    const filename = 'revclamp-contactpulse-output.json';
    const blob = new Blob([serialized], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 1000);
    els.statusBanner.dataset.state = 'ok';
    els.statusBanner.textContent = `Download started for ${filename} (${serialized.length} chars).`;
  }

  async function executeSelectedTool() {
    const requestToken = ++state.activeRequestToken;
    clearExportableResultState(true, true);
    if (els.rawJsonBox) els.rawJsonBox.textContent = '{}';
    state.lastNextPageToken = null;
    if (els.nextPageBtn) els.nextPageBtn.hidden = true;

    const args = collectToolArguments();
    const reqId = `ui_${state.rpcRequestId++}`;
    const toolNameAtStart = state.selectedToolName;
    const humanToolLabel = getHumanToolTitle(toolNameAtStart);
    els.statusBanner.dataset.state = 'pending';
    els.statusBanner.textContent = `Running ${humanToolLabel}...`;

    try {
      const response = await fetch('/api/mcp', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: reqId,
          method: 'tools/call',
          params: {
            name: toolNameAtStart,
            arguments: args,
          },
        }),
      });
      if (requestToken !== state.activeRequestToken) return;

      const rawText = await response.text();
      if (requestToken !== state.activeRequestToken) return;

      const byteLength = new TextEncoder().encode(rawText).length;
      els.envelopeBytesValue.textContent = `${byteLength} B`;

      let rpcEnvelope;
      try {
        rpcEnvelope = JSON.parse(rawText);
      } catch {
        clearExportableResultState(true, false);
        state.lastNextPageToken = null;
        if (els.nextPageBtn) els.nextPageBtn.hidden = true;
        els.statusBanner.dataset.state = 'error';
        els.statusBanner.textContent = `HTTP ${response.status}: Non-JSON response received.`;
        els.rawJsonBox.textContent = rawText;
        return;
      }

      els.rawJsonBox.textContent = JSON.stringify(rpcEnvelope, null, 2);

      if (rpcEnvelope.ok === false && typeof rpcEnvelope.error === 'string') {
        clearExportableResultState(true, false);
        state.lastNextPageToken = null;
        if (els.nextPageBtn) els.nextPageBtn.hidden = true;
        els.statusBanner.dataset.state = 'error';
        els.statusBanner.textContent = `HTTP ${response.status} Error: ${rpcEnvelope.error}`;
        return;
      }

      if (rpcEnvelope.error) {
        clearExportableResultState(true, false);
        state.lastNextPageToken = null;
        if (els.nextPageBtn) els.nextPageBtn.hidden = true;
        els.statusBanner.dataset.state = 'error';
        els.statusBanner.textContent = humanizeRpcErrorMessage(rpcEnvelope.error);
        return;
      }

      const rawStructured = rpcEnvelope.result?.structuredContent;
      const hasValidStructured = Boolean(
        rawStructured && typeof rawStructured === 'object' && !Array.isArray(rawStructured)
      );
      const structured = hasValidStructured ? rawStructured : {};
      const isResultError = Boolean(rpcEnvelope.result?.isError);
      if (!isResultError && hasValidStructured) {
        state.lastResultPayload = structured;
        setExportButtonsEnabled(true);
      } else {
        clearExportableResultState(true, false);
      }

      const chargedCount = Number(structured.chargedEventCount || 0);
      els.billingModeValue.textContent =
        chargedCount > 0
          ? `Confirmed charged (${chargedCount})`
          : 'Local mode - not billed';

      const countVal =
        Array.isArray(structured.items) && structured.items.length > 0
          ? structured.items.length
          : structured.deliveredCount !== undefined
            ? structured.deliveredCount
            : structured.extractedCount !== undefined
              ? structured.extractedCount
              : structured.domainProfile || structured.email
                ? 1
                : 0;
      els.extractedCountValue.textContent = String(countVal);

      const pagStatus = structured.pagination?.paginationStatus || structured.status || 'OK';
      els.paginationStatusValue.textContent = pagStatus;

      const nextToken = structured.pagination?.nextPageToken || null;
      state.lastNextPageToken = nextToken;
      els.nextPageBtn.hidden = !nextToken;

      const omittedCount = Number(structured.omittedItemCount ?? 0);
      const isByteTruncated = Boolean(structured.truncatedForMcpByteCeiling);
      const isPartialMultiPage =
        pagStatus === 'PARTIAL_PAGES_HAS_MORE' || pagStatus === 'DEADLINE_REACHED_HAS_MORE';
      const truncationSuffix =
        omittedCount > 0
          ? nextToken
            ? ` (${omittedCount} omitted to fit the 30 KB limit - click Load next page to continue).`
            : ` (${omittedCount} omitted to fit the 30 KB limit).`
          : isByteTruncated
            ? ' (some details were trimmed to fit the 30 KB limit).'
            : isPartialMultiPage
              ? nextToken
                ? ' (partial multi-domain results preserved - click Load next page to continue).'
                : ' (partial multi-domain results preserved).'
              : '.';

      els.statusBanner.dataset.state = isResultError
        ? 'error'
        : isPartialMultiPage
          ? 'warn'
          : 'ok';
      els.statusBanner.textContent = isResultError
        ? `Run halted (${structured.status || 'ERROR'}): ${structured.reason || 'Upstream error occurred.'}`
        : `Completed ${humanToolLabel} (${countVal} matching ${countVal === 1 ? 'record' : 'records'})${truncationSuffix}`;

      renderResultCards(structured);
    } catch (err) {
      if (requestToken !== state.activeRequestToken) return;
      clearExportableResultState(true, false);
      if (els.rawJsonBox) {
        els.rawJsonBox.textContent = '{}';
      }
      state.lastNextPageToken = null;
      if (els.nextPageBtn) {
        els.nextPageBtn.hidden = true;
      }
      els.statusBanner.dataset.state = 'error';
      els.statusBanner.textContent = `Request failed: ${err?.message || String(err)}`;
    }
  }

  async function initPlayground() {
    try {
      const res = await fetch('/api/schema');
      const data = await res.json();
      state.tools = Array.isArray(data.tools) ? data.tools : [];
    } catch {
      state.tools = [];
    }

    clearChildren(els.toolSelect);
    for (const tool of state.tools) {
      const optLabel = TOOL_UI_META[tool.name]?.title || tool.title || tool.name;
      const opt = createEl('option', '', optLabel);
      opt.value = tool.name;
      if (tool.name === state.selectedToolName) {
        opt.selected = true;
      }
      els.toolSelect.appendChild(opt);
    }

    renderSchemaFields();

    els.toolSelect.addEventListener('change', () => {
      state.activeRequestToken += 1;
      state.selectedToolName = els.toolSelect.value;
      state.lastNextPageToken = null;
      els.nextPageBtn.hidden = true;
      clearExportableResultState(true, true);
      els.rawJsonBox.textContent = '{}';
      els.statusBanner.dataset.state = 'idle';
      els.statusBanner.textContent = `Ready to run ${getHumanToolTitle(state.selectedToolName)}.`;
      renderSchemaFields();
    });

    els.loadPreviewsCheckbox.addEventListener('change', () => {
      state.loadPreviewsOptIn = Boolean(els.loadPreviewsCheckbox.checked);
      if (state.lastResultPayload) {
        renderResultCards(state.lastResultPayload);
      }
    });

    els.runBtn.addEventListener('click', () => {
      executeSelectedTool();
    });

    els.nextPageBtn.addEventListener('click', () => {
      if (!state.lastNextPageToken) return;
      const pageTokenInput = document.getElementById('field-pageToken');
      if (pageTokenInput) {
        pageTokenInput.value = state.lastNextPageToken;
      }
      executeSelectedTool();
    });

    if (els.copyJsonBtn) {
      els.copyJsonBtn.addEventListener('click', () => {
        copyExportableJson();
      });
    }

    if (els.downloadJsonBtn) {
      els.downloadJsonBtn.addEventListener('click', () => {
        downloadExportableJson();
      });
    }

    if (els.dynamicFields) {
      els.dynamicFields.addEventListener('keydown', (e) => {
        if (e.isComposing || e.repeat) return;
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
          const tag = String(e.target?.tagName || '').toUpperCase();
          if (tag === 'INPUT' || tag === 'SELECT') {
            e.preventDefault();
            if (els.statusBanner?.dataset.state !== 'pending') {
              executeSelectedTool();
            }
          }
        }
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initPlayground);
  } else {
    initPlayground();
  }
})();
