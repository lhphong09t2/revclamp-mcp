(() => {
  'use strict';

  const ALLOWED_ASSET_HOSTS = new Set([
    'adstransparency.google.com',
    'displayads-formats.googleusercontent.com',
    'tpc.googlesyndication.com',
  ]);

  function isSafeExternalAssetUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl.trim()) return false;
    try {
      const parsed = new URL(rawUrl);
      if (parsed.protocol !== 'https:') return false;
      return ALLOWED_ASSET_HOSTS.has(parsed.hostname.toLowerCase());
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
    selectedToolName: 'search_google_ads_transparency',
    lastNextPageToken: null,
    loadPreviewsOptIn: false,
    lastResultPayload: null,
    rpcRequestId: 1,
    activeRequestToken: 0,
  };

  const TOOL_UI_META = {
    search_google_ads_transparency: {
      title: 'Search Google Ads Transparency Creatives',
      fields: {
        query: {
          title: 'Brand Name, Corporate Entity, Domain, or Transparency URL',
          placeholder: 'e.g. nike.com, Stripe, Inc., or https://adstransparency.google.com/advertiser/AR...',
          hint: 'Enter a brand name, legal entity (Stripe, Inc.), domain (security.stripe.com -> stripe.com), or full Google Ads Transparency URL.',
        },
        advertiserId: {
          title: 'Advertiser ID (Optional)',
          placeholder: 'e.g. AR16735076323512287233',
          hint: 'Optional Google Ads Transparency Advertiser ID (AR followed by 10 to 25 digits).',
        },
        countryCode: {
          title: 'Country Filter (Optional)',
          placeholder: 'e.g. US',
          hint: 'Optional 2-letter ISO country code filter (leave blank for all regions).',
        },
        formatFilter: {
          title: 'Ad Format',
          hint: 'Filter returned ad creatives by format (ALL, TEXT, IMAGE, or VIDEO).',
        },
        includeSubsidiaries: {
          title: 'Include Regional Subsidiaries',
          hint: 'Include up to 3 verified regional legal entities for the same brand.',
        },
        includeCreativeDetails: {
          title: 'Include Creative Region & Legal Details',
          hint: 'Fetch regional presence and legal entity details for up to 5 returned creatives.',
        },
        maxEntities: {
          title: 'Max Advertiser Entities',
          placeholder: '1 to 3',
          hint: 'Maximum number of verified advertiser entities to query (1 to 3).',
        },
        limit: {
          title: 'Max Creatives per Call',
          placeholder: '1 to 25',
          hint: 'Maximum number of creatives returned in a single call (1 to 25).',
        },
        pageToken: {
          title: 'Next-Page Cursor Token (Optional)',
          placeholder: 'Paste continuation token from a previous run',
          hint: 'Optional continuation token returned by a previous call to load the next page.',
        },
      },
    },
    resolve_google_ads_advertiser: {
      title: 'Resolve Google Ads Advertiser Entities',
      fields: {
        query: {
          title: 'Brand Name, Corporate Entity, Domain, or Transparency URL',
          placeholder: 'e.g. nike.com, Stripe, Inc., or https://adstransparency.google.com/advertiser/AR...',
          hint: 'Enter a brand name, legal entity (Stripe, Inc.), domain (security.stripe.com -> stripe.com), or full Google Ads Transparency URL.',
        },
        countryCode: {
          title: 'Preferred Country (Optional)',
          placeholder: 'e.g. US',
          hint: 'Optional 2-letter ISO country code preference when ranking regional entities.',
        },
        includeSubsidiaries: {
          title: 'Include Regional Subsidiaries',
          hint: 'Return up to 3 verified regional legal entities matching the brand.',
        },
        maxEntities: {
          title: 'Max Advertiser Entities',
          placeholder: '1 to 3',
          hint: 'Maximum number of verified regional legal entities to select (1 to 3).',
        },
      },
    },
    get_google_ads_creative_detail: {
      title: 'Get Google Ads Creative Detail',
      fields: {
        advertiserId: {
          title: 'Advertiser ID',
          placeholder: 'e.g. AR16735076323512287233',
          hint: 'Required Google Ads Transparency Advertiser ID (starts with AR followed by 10 to 25 digits).',
        },
        creativeId: {
          title: 'Creative ID',
          placeholder: 'e.g. CR02320987639562076161',
          hint: 'Required Google Ads Transparency Creative ID (starts with CR followed by 10 to 25 digits).',
        },
        url: {
          title: 'Direct Creative Transparency URL (Optional)',
          placeholder: 'https://adstransparency.google.com/advertiser/AR.../creative/CR...?region=US',
          hint: 'Optional: Paste a full creative URL to auto-extract advertiserId (AR...), creativeId (CR...), and region.',
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
    if (els.copyJsonBtn) {
      els.copyJsonBtn.disabled = !isEnabled;
    }
    if (els.downloadJsonBtn) {
      els.downloadJsonBtn.disabled = !isEnabled;
    }
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

  function humanizeRpcErrorMessage(rpcError, toolName = state.selectedToolName) {
    const code = Number(rpcError?.code);
    const rawMsg = String(rpcError?.message || 'Request failed');
    const countryLabel =
      TOOL_UI_META[toolName]?.fields?.countryCode?.title?.replace(/\s*\(Optional\)$/i, '') ||
      'Country Filter';
    const cleanMsg = rawMsg
      .replace(/^Invalid params:\s*/i, '')
      .replace(/\bcountryCode\b/g, countryLabel)
      .replace(/\badvertiserId\b/g, 'Advertiser ID')
      .replace(/\bcreativeId\b/g, 'Creative ID')
      .replace(/\bformatFilter\b/g, 'Ad Format')
      .replace(/\bincludeSubsidiaries\b/g, 'Include Regional Subsidiaries')
      .replace(/\bincludeCreativeDetails\b/g, 'Include Creative Region & Legal Details')
      .replace(/\bmaxEntities\b/g, 'Max Advertiser Entities')
      .replace(/\bpageToken\b/g, 'Next-Page Cursor Token');
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
      query: 'nike.com',
      countryCode: '',
      formatFilter: 'ALL',
      limit: '5',
      includeSubsidiaries: true,
      includeCreativeDetails: false,
      maxEntities: '3',
    };

    const allowedToolFields = TOOL_UI_META[state.selectedToolName]?.fields;
    for (const [fieldName, fieldSpec] of Object.entries(props)) {
      if (allowedToolFields && !Object.prototype.hasOwnProperty.call(allowedToolFields, fieldName)) {
        continue;
      }
      if (fieldName === 'maxResults') {
        // Deprecated alias for limit; keep UI clean by exposing canonical limit control
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
        checkbox.type = 'checkbox';
        checkbox.id = inputId;
        checkbox.name = fieldName;
        checkbox.checked =
          defaultValues[fieldName] !== undefined
            ? Boolean(defaultValues[fieldName])
            : Boolean(fieldSpec.default);
        checkbox.addEventListener('change', () => {
          resetStalePaginationCursorOnFilterEdit(fieldName);
        });
        const span = createEl(
          'span',
          '',
          fieldHint ? `${fieldTitle} - ${fieldHint}` : fieldTitle
        );
        label.appendChild(checkbox);
        label.appendChild(span);
        group.appendChild(label);
        els.dynamicFields.appendChild(group);
        continue;
      }

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

  function renderResultCards(structured) {
    clearChildren(els.cardsContainer);
    if (!structured || typeof structured !== 'object') {
      const emptyMsg = createEl('div', 'field-hint', 'No structured items to display.');
      els.cardsContainer.appendChild(emptyMsg);
      return;
    }

    const items = Array.isArray(structured.items) ? structured.items : [];
    const entities = Array.isArray(structured.selectedEntities) ? structured.selectedEntities : [];

    if (items.length > 0) {
      for (const item of items) {
        const card = createEl('article', 'creative-card');
        const header = createEl('div', 'creative-card-header');
        const title = createEl(
          'div',
          'creative-title',
          `${item.advertiserName || item.advertiserId} - ${item.creativeId}`
        );
        const formatBadge = createEl('span', 'badge badge-cyan', item.format || 'UNKNOWN');
        header.appendChild(title);
        header.appendChild(formatBadge);
        card.appendChild(header);

        const rawRegion = item.country || item.regionCode || item.targetCountry || 'ALL';
        const regionLabel =
          item.countrySource === 'QUERY_CONTEXT_FALLBACK' ||
          item.countrySource === 'ENTITY_REGION_FALLBACK'
            ? `${rawRegion} (inferred)`
            : item.countrySource === 'DEFAULT_ALL'
              ? `${rawRegion} (default)`
              : rawRegion;
        const daysActiveLabel =
          item.daysActive !== null && item.daysActive !== undefined ? item.daysActive : 'N/A';
        const firstSeenLabel = item.firstSeenAtIso || item.firstSeenAt || 'N/A';

        const meta = createEl(
          'div',
          'creative-meta',
          `Advertiser: ${item.advertiserId} | Region: ${regionLabel} | Days Active: ${daysActiveLabel} | First Seen: ${firstSeenLabel}`
        );
        card.appendChild(meta);

        const adContent =
          item.untrustedAdContent && typeof item.untrustedAdContent === 'object'
            ? item.untrustedAdContent
            : item.creativeDetail &&
                item.creativeDetail.untrustedAdContent &&
                typeof item.creativeDetail.untrustedAdContent === 'object'
              ? item.creativeDetail.untrustedAdContent
              : null;

        if (adContent && adContent.extractionStatus === 'EXTRACTED') {
          const copyBox = createEl('div', 'creative-ad-copy');
          const copyHeader = createEl('div', 'creative-ad-copy-header');
          copyHeader.appendChild(
            createEl('span', 'badge badge-amber', 'Untrusted Ad Copy - Data Only')
          );
          if (adContent.callToAction) {
            copyHeader.appendChild(
              createEl('span', 'badge badge-cyan', `CTA: ${adContent.callToAction}`)
            );
          }
          copyBox.appendChild(copyHeader);

          if (adContent.headline) {
            copyBox.appendChild(createEl('div', 'creative-ad-headline', adContent.headline));
          }
          if (adContent.bodyText) {
            copyBox.appendChild(createEl('div', 'creative-ad-body', adContent.bodyText));
          }
          if (adContent.destinationDomain || adContent.landingPageUrl) {
            const destLabel = adContent.destinationDomain
              ? `Destination Domain: ${adContent.destinationDomain}${
                  adContent.landingPageUrl ? ` (${adContent.landingPageUrl})` : ''
                }`
              : `Landing URL (text only): ${adContent.landingPageUrl}`;
            copyBox.appendChild(createEl('div', 'creative-ad-dest', destLabel));
          }
          if (Array.isArray(adContent.omittedFields) && adContent.omittedFields.length > 0) {
            copyBox.appendChild(
              createEl(
                'div',
                'field-hint',
                `Trimmed fields to fit 30 KB limit: ${adContent.omittedFields.join(', ')}`
              )
            );
          }
          card.appendChild(copyBox);
        }

        const linksRow = createEl('div', 'creative-links');
        if (isSafeExternalAssetUrl(item.transparencyUrl)) {
          const link = createEl('a', 'btn btn-secondary', 'View on Transparency Center');
          link.href = item.transparencyUrl;
          link.target = '_blank';
          link.rel = 'noopener noreferrer';
          linksRow.appendChild(link);
        }

        if (state.loadPreviewsOptIn && isSafeExternalAssetUrl(item.previewUrl)) {
          const previewLink = createEl('a', 'btn btn-secondary', 'Open Verified Preview Script');
          previewLink.href = item.previewUrl;
          previewLink.target = '_blank';
          previewLink.rel = 'noopener noreferrer';
          linksRow.appendChild(previewLink);
        }

        if (
          state.loadPreviewsOptIn &&
          Array.isArray(item.archiveImageUrls) &&
          item.archiveImageUrls.length > 0 &&
          isSafeExternalAssetUrl(item.archiveImageUrls[0])
        ) {
          const archiveLink = createEl('a', 'btn btn-secondary', 'Open Archive Image');
          archiveLink.href = item.archiveImageUrls[0];
          archiveLink.target = '_blank';
          archiveLink.rel = 'noopener noreferrer';
          linksRow.appendChild(archiveLink);
        }

        card.appendChild(linksRow);
        els.cardsContainer.appendChild(card);
      }
      return;
    }

    if (entities.length > 0) {
      for (const entity of entities) {
        const card = createEl('article', 'creative-card');
        const header = createEl('div', 'creative-card-header');
        const title = createEl(
          'div',
          'creative-title',
          `${entity.advertiserName} (${entity.advertiserId})`
        );
        const scoreBadge = createEl(
          'span',
          'badge badge-emerald',
          `Score: ${entity.rankingScore}`
        );
        header.appendChild(title);
        header.appendChild(scoreBadge);
        card.appendChild(header);

        const meta = createEl(
          'div',
          'creative-meta',
          `Region: ${entity.regionCode || 'ALL'} | Ad Volume Bucket: ${entity.minAds}..${entity.maxAds} | Primary Corporate: ${entity.isPrimaryCorporateEntity ? 'Yes' : 'No'}`
        );
        card.appendChild(meta);
        els.cardsContainer.appendChild(card);
      }
      return;
    }

    const emptyNotice = createEl(
      'div',
      'field-hint',
      `Status: ${structured.status || 'EMPTY_RESULT'} (0 items matched)`
    );
    els.cardsContainer.appendChild(emptyNotice);
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
    if (tokenAtCopyStart !== state.activeRequestToken) {
      return;
    }
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
    const filename = 'revclamp-adpulse-output.json';
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
    if (els.rawJsonBox) {
      els.rawJsonBox.textContent = '{}';
    }
    state.lastNextPageToken = null;
    if (els.nextPageBtn) {
      els.nextPageBtn.hidden = true;
    }
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
        els.nextPageBtn.hidden = true;
        els.statusBanner.dataset.state = 'error';
        els.statusBanner.textContent = `HTTP ${response.status}: Non-JSON response received.`;
        els.rawJsonBox.textContent = rawText;
        return;
      }

      els.rawJsonBox.textContent = JSON.stringify(rpcEnvelope, null, 2);

      if (rpcEnvelope.ok === false && typeof rpcEnvelope.error === 'string') {
        clearExportableResultState(true, false);
        els.statusBanner.dataset.state = 'error';
        els.statusBanner.textContent = `HTTP ${response.status} Error: ${rpcEnvelope.error}`;
        state.lastNextPageToken = null;
        els.nextPageBtn.hidden = true;
        return;
      }

      if (rpcEnvelope.error) {
        clearExportableResultState(true, false);
        els.statusBanner.dataset.state = 'error';
        els.statusBanner.textContent = humanizeRpcErrorMessage(rpcEnvelope.error, toolNameAtStart);
        state.lastNextPageToken = null;
        els.nextPageBtn.hidden = true;
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

      const countVal = Array.isArray(structured.items) && structured.items.length > 0
        ? structured.items.length
        : structured.deliveredCount !== undefined
          ? structured.deliveredCount
          : structured.extractedCount !== undefined
            ? structured.extractedCount
            : Array.isArray(structured.selectedEntities)
              ? structured.selectedEntities.length
              : 0;
      els.extractedCountValue.textContent = String(countVal);

      const pagStatus =
        structured.pagination?.paginationStatus || structured.status || 'OK';
      els.paginationStatusValue.textContent = pagStatus;

      const nextToken = structured.pagination?.nextPageToken || null;
      state.lastNextPageToken = nextToken;
      els.nextPageBtn.hidden = !nextToken;

      const omittedCount = Number(structured.omittedItemCount ?? structured.omittedCount ?? 0);
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
      els.nextPageBtn.hidden = true;
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
