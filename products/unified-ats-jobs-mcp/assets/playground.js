(() => {
  'use strict';

  const ALLOWED_EXTERNAL_HOSTS_RE =
    /^(boards\.greenhouse\.io|job-boards\.greenhouse\.io|boards-api\.greenhouse\.io|jobs\.ashbyhq\.com|api\.ashbyhq\.com|jobs\.lever\.co|api\.lever\.co|jobs\.smartrecruiters\.com|api\.smartrecruiters\.com|[a-z0-9-]+\.wd[1-5]\.myworkdayjobs\.com)$/i;

  function isSafeExternalJobUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl.trim()) return false;
    try {
      const parsed = new URL(rawUrl);
      if (parsed.protocol !== 'https:') return false;
      return ALLOWED_EXTERNAL_HOSTS_RE.test(parsed.hostname.toLowerCase());
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
    selectedToolName: 'search_ats_job_postings',
    lastNextPageToken: null,
    loadPreviewsOptIn: false,
    lastResultPayload: null,
    rpcRequestId: 1,
    activeRequestToken: 0,
  };

  const TOOL_UI_META = {
    search_ats_job_postings: {
      title: 'Search Unified 5-in-1 B2B ATS Job Postings',
      fields: {
        query: {
          title: 'Company Slug, Brand Name, Domain, or Career URL',
          placeholder: 'e.g. linear, Stripe, Inc., stripe.com, or https://about.gitlab.com/jobs',
          hint: 'Enter a company slug, legal name, B2B domain (auto-strips 23+ subdomains like about.gitlab.com -> gitlab), or direct Greenhouse/Workday/Ashby/Lever/SmartRecruiters URL.',
        },
        provider: {
          title: 'ATS Provider Override (Optional)',
          hint: 'Leave as AUTO to automatically detect from URL or company directory.',
        },
        companySlug: {
          title: 'Explicit Company Slug (Optional)',
          placeholder: 'e.g. linear',
          hint: 'Optional explicit ATS board slug.',
        },
        careerUrl: {
          title: 'Direct Career Board URL (Optional)',
          placeholder: 'https://jobs.ashbyhq.com/linear',
          hint: 'Optional direct HTTPS URL to a supported ATS career board.',
        },
        searchKeyword: {
          title: 'Role or Tech Keyword Filter (Optional)',
          placeholder: 'e.g. Engineer, Python, Security',
          hint: 'Case-insensitive filter across job title, department, location, and techStackKeywords.',
        },
        workplaceType: {
          title: 'Workplace Type Filter (Optional)',
          hint: 'Filter jobs by REMOTE, HYBRID, ONSITE, or ANY.',
        },
        departmentKeyword: {
          title: 'Department Filter (Optional)',
          placeholder: 'e.g. Engineering, Product, Sales',
          hint: 'Case-insensitive substring filter on normalized department.',
        },
        countryCode: {
          title: 'Country Filter (ISO-2, Optional)',
          placeholder: 'e.g. US, GB, DE',
          hint: 'Optional 2-letter ISO-3166-1 alpha-2 country code filter.',
        },
        workdayTenant: {
          title: 'Workday Tenant (Optional)',
          placeholder: 'e.g. nvidia',
          hint: 'Optional explicit Workday tenant subdomain when provider is WORKDAY.',
        },
        workdaySite: {
          title: 'Workday Career Site (Optional)',
          placeholder: 'e.g. NVIDIAExternalCareerSite',
          hint: 'Optional explicit Workday CXS career site identifier.',
        },
        wdInstance: {
          title: 'Workday Instance (Optional)',
          placeholder: 'e.g. wd5, wd1',
          hint: 'Optional Workday cluster instance (wd1, wd3, wd5, wd12).',
        },
        limit: {
          title: 'Max Job Postings per Call',
          placeholder: '1 to 25',
          hint: 'Maximum number of normalized job postings returned in a single call (1 to 25).',
        },
        cursor: {
          label: 'Pagination Cursor (Optional)',
          title: 'Pagination Cursor (Optional)',
          placeholder: 'Paste pagination.nextCursor to fetch next page...',
          hint: 'Auto-clears whenever you edit filters above.',
        },
      },
    },
    resolve_company_ats_board: {
      title: 'Resolve Company ATS Board & Provider',
      fields: {
        query: {
          title: 'Company Slug, Brand Name, Domain, or Career URL',
          placeholder: 'e.g. linear, Stripe, Inc., stripe.com, or https://about.gitlab.com/jobs',
          hint: 'Enter a company slug, legal name, B2B domain (auto-strips 23+ subdomains like about.gitlab.com -> gitlab), or direct Greenhouse/Workday/Ashby/Lever/SmartRecruiters URL.',
        },
        provider: {
          title: 'ATS Provider Override (Optional)',
          hint: 'Optional explicit ATS provider hint.',
        },
        companySlug: {
          title: 'Explicit Company Slug (Optional)',
          placeholder: 'e.g. linear',
          hint: 'Optional explicit ATS board slug.',
        },
        careerUrl: {
          title: 'Direct Career Board URL (Optional)',
          placeholder: 'https://boards.greenhouse.io/stripe',
          hint: 'Optional direct HTTPS URL to a supported ATS career board.',
        },
        workdayTenant: {
          title: 'Workday Tenant (Optional)',
          placeholder: 'e.g. nvidia',
          hint: 'Optional explicit Workday tenant subdomain.',
        },
        workdaySite: {
          title: 'Workday Career Site (Optional)',
          placeholder: 'e.g. NVIDIAExternalCareerSite',
          hint: 'Optional explicit Workday CXS career site identifier.',
        },
        wdInstance: {
          title: 'Workday Instance (Optional)',
          placeholder: 'e.g. wd5, wd1',
          hint: 'Optional Workday cluster instance (wd1, wd3, wd5, wd12).',
        },
      },
    },
    get_ats_job_posting_detail: {
      title: 'Get Normalized ATS Job Posting Detail',
      fields: {
        jobId: {
          title: 'Canonical Job ID or Raw Job ID',
          placeholder: 'e.g. ASHBY:linear:403ef663-c352-49c5-b42f-9761c5ab25ab',
          hint: 'Required canonical jobId (PROVIDER:companySlug:rawJobId) or raw ID paired with query.',
        },
        query: {
          title: 'Company Slug or Career URL (Optional)',
          placeholder: 'e.g. linear',
          hint: 'Optional company slug when jobId is passed as a raw provider ID.',
        },
        provider: {
          title: 'ATS Provider (Optional)',
          hint: 'Optional ATS provider override.',
        },
        companySlug: {
          title: 'Company Slug (Optional)',
          placeholder: 'e.g. linear',
          hint: 'Optional explicit company slug.',
        },
        careerUrl: {
          title: 'Direct Career Board URL (Optional)',
          placeholder: 'https://jobs.ashbyhq.com/linear',
          hint: 'Optional direct HTTPS URL to a supported ATS career board.',
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
      .replace(/\bworkplaceType\b/g, 'Workplace Type')
      .replace(/\bsearchKeyword\b/g, 'Role or Tech Keyword')
      .replace(/\bdepartmentKeyword\b/g, 'Department Filter')
      .replace(/\b(?:cursor|pageToken)\b/g, 'Pagination Cursor');
    if (/CONFLICTING_PARAMETER_ALIASES/i.test(rawMsg)) {
      return 'Conflicting input aliases provided. Please pass a single target or matching alias values.';
    }
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
    if (changedFieldName === 'cursor' || changedFieldName === 'pageToken') return;
    state.activeRequestToken += 1;
    if (els.statusBanner && els.statusBanner.dataset.state === 'pending') {
      els.statusBanner.dataset.state = 'idle';
      els.statusBanner.textContent = 'Ready - filter updated; click Run to execute.';
    }
    const cursorInput = document.getElementById('field-cursor') || document.getElementById('field-pageToken');
    if (cursorInput && cursorInput.value) {
      cursorInput.value = '';
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
      query: 'linear',
      provider: 'AUTO',
      workplaceType: 'ANY',
      limit: '5',
    };

    const allowedToolFields = TOOL_UI_META[state.selectedToolName]?.fields;
    for (const [fieldName, fieldSpec] of Object.entries(props)) {
      if (allowedToolFields && !Object.prototype.hasOwnProperty.call(allowedToolFields, fieldName)) {
        continue;
      }
      if (fieldName === 'maxResults') {
        continue;
      }

      const uiFieldMeta = TOOL_UI_META[state.selectedToolName]?.fields?.[fieldName] || {};
      const fieldTitle = uiFieldMeta.title || fieldSpec.title || fieldName;
      const fieldHint = uiFieldMeta.hint || fieldSpec.description || '';
      const fieldPlaceholder = uiFieldMeta.placeholder || fieldTitle;

      const group = createEl('div', 'field-group');
      const inputId = `field-${fieldName}`;

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

  function formatCompSummary(comp) {
    if (!comp || typeof comp !== 'object' || comp.minAmount === null) {
      return 'Not Disclosed';
    }
    const cur = comp.currency || 'USD';
    const minStr = Number(comp.minAmount).toLocaleString('en-US');
    const maxStr =
      comp.maxAmount !== null && comp.maxAmount !== comp.minAmount
        ? ` - ${Number(comp.maxAmount).toLocaleString('en-US')}`
        : '';
    return `${cur} ${minStr}${maxStr} / ${comp.interval || 'YEAR'}`;
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
        const card = createEl('article', 'job-card');
        const header = createEl('div', 'job-card-header');
        const title = createEl(
          'div',
          'job-title',
          `${item.companyName || item.companySlug} - ${item.title}`
        );
        const badgesWrap = createEl('div', 'job-tech-row');
        badgesWrap.appendChild(createEl('span', 'badge badge-emerald', item.atsProvider || 'ATS'));
        badgesWrap.appendChild(
          createEl('span', 'badge badge-cyan', item.workplaceType || 'UNKNOWN')
        );
        header.appendChild(title);
        header.appendChild(badgesWrap);
        card.appendChild(header);

        const compText = formatCompSummary(item.compensation);
        const meta = createEl(
          'div',
          'job-meta',
          `ID: ${item.jobId} | Dept: ${item.department || 'General'} | Location: ${item.locationRaw || 'Unspecified'} (${item.countryIso2 || 'N/A'}) | Level: ${item.seniorityLevel || 'MID'} | Comp: ${compText}`
        );
        card.appendChild(meta);

        if (Array.isArray(item.techStackKeywords) && item.techStackKeywords.length > 0) {
          const techRow = createEl('div', 'job-tech-row');
          for (const kw of item.techStackKeywords) {
            techRow.appendChild(createEl('span', 'badge', kw));
          }
          card.appendChild(techRow);
        }

        if (item.untrustedJobContent && item.untrustedJobContent.plainTextExcerpt) {
          const excerptBox = createEl('div', 'job-excerpt-box');
          const excerptHeader = createEl('div', 'job-excerpt-header');
          excerptHeader.appendChild(
            createEl('span', 'badge badge-amber', 'Untrusted Job Excerpt - Data Only')
          );
          excerptBox.appendChild(excerptHeader);
          excerptBox.appendChild(
            createEl('div', 'job-excerpt-body', item.untrustedJobContent.plainTextExcerpt)
          );
          card.appendChild(excerptBox);
        }

        if (state.loadPreviewsOptIn && isSafeExternalJobUrl(item.applyUrl)) {
          const linksRow = createEl('div', 'job-links');
          const link = createEl('a', 'btn btn-secondary', 'Open Verified Apply URL');
          link.href = item.applyUrl;
          link.target = '_blank';
          link.rel = 'noopener noreferrer';
          linksRow.appendChild(link);
          card.appendChild(linksRow);
        }

        els.cardsContainer.appendChild(card);
      }
      return;
    }

    if (structured.boardTarget && typeof structured.boardTarget === 'object') {
      const bt = structured.boardTarget;
      const card = createEl('article', 'job-card');
      const header = createEl('div', 'job-card-header');
      header.appendChild(
        createEl('div', 'job-title', `${bt.companyName || bt.companySlug} (${bt.provider})`)
      );
      header.appendChild(createEl('span', 'badge badge-emerald', bt.resolutionSource || 'RESOLVED'));
      card.appendChild(header);
      card.appendChild(
        createEl(
          'div',
          'job-meta',
          `Provider: ${bt.provider} | Company Slug: ${bt.companySlug} | Career Board: ${bt.boardUrl || 'N/A'}`
        )
      );
      els.cardsContainer.appendChild(card);
      return;
    }

    els.cardsContainer.appendChild(
      createEl(
        'div',
        'field-hint',
        `Status: ${structured.status || 'EMPTY_RESULT'} (0 job postings matched)`
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
    const filename = 'revclamp-talentpulse-output.json';
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
              : structured.boardTarget
                ? 1
                : 0;
      els.extractedCountValue.textContent = String(countVal);

      const pagStatus = structured.pagination?.paginationStatus || structured.status || 'OK';
      els.paginationStatusValue.textContent = pagStatus;

      const nextToken = structured.pagination?.nextCursor || structured.pagination?.nextPageToken || null;
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
                ? ' (partial multi-page results preserved - click Load next page to continue).'
                : ' (partial multi-page results preserved).'
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
      const cursorInput = document.getElementById('field-cursor') || document.getElementById('field-pageToken');
      if (cursorInput) {
        cursorInput.value = state.lastNextPageToken;
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
