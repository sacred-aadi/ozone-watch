(function () {
  const scanForm = document.getElementById('scanForm');
  const scanInput = document.getElementById('scanInput');
  const scanStatus = document.getElementById('scanStatus');
  const scanTarget = document.getElementById('scanTarget');
  const scanRiskWrap = document.getElementById('scanRiskWrap');
  const scanCount = document.getElementById('scanCount');
  const scanDataTypes = document.getElementById('scanDataTypes');
  const scanBreaches = document.getElementById('scanBreaches');
  const scanActions = document.getElementById('scanActions');
  const scanSources = document.getElementById('scanSources');
  const scanIntel = document.getElementById('scanIntel');
  const scanTriggers = document.querySelectorAll('.js-scan-trigger');

  const pwdForm = document.getElementById('pwdForm');
  const pwdInput = document.getElementById('pwdInput');
  const pwdStatus = document.getElementById('pwdStatus');
  const pwdResult = document.getElementById('pwdResult');

  let scanning = false;
  let checkingPwd = false;

  function renderList(node, items, emptyText) {
    if (!node) return;
    node.innerHTML = '';
    if (!items.length) {
      const li = document.createElement('li');
      li.textContent = emptyText;
      node.appendChild(li);
      return;
    }
    items.forEach((text) => {
      const li = document.createElement('li');
      li.textContent = text;
      node.appendChild(li);
    });
  }

  function setStatus(text, kind) {
    if (!scanStatus) return;
    scanStatus.textContent = text;
    scanStatus.className = 'scan-status' + (kind ? ' ' + kind : '');
  }

  function setRisk(risk) {
    const map = { LOW: 'risk-low', MEDIUM: 'risk-medium', HIGH: 'risk-high' };
    if (!scanRiskWrap) return;
    scanRiskWrap.innerHTML =
      '<span class="risk-pill ' + (map[risk] || 'risk-low') + '">' + risk + '</span>';
  }

  function formatBreachRows(breaches) {
    return (breaches || []).map((b) => {
      const types = (b.data_classes || []).join(', ');
      const provider = b.provider ? ' [' + b.provider + ']' : '';
      return (
        b.source +
        ' (' +
        (b.year || 'N/A') +
        ')' +
        provider +
        (types ? ' | leaked: ' + types : '')
      );
    });
  }

  function formatIntel(data) {
    if (!data || !data.email_intel || !Object.keys(data.email_intel).length) {
      return ['No email intel (phone scan or source unavailable).'];
    }
    const intel = data.email_intel;
    const rows = [];
    if (intel.domain) rows.push('Domain: ' + intel.domain);
    rows.push('Format valid: ' + (intel.format_valid ? 'yes' : 'no'));
    rows.push('Disposable email: ' + (intel.disposable ? 'yes — higher scam risk' : 'no'));
    rows.push('DNS valid: ' + (intel.dns_valid ? 'yes' : 'no'));
    if (data.leakcheck_hits) rows.push('LeakCheck corpus hits: ' + data.leakcheck_hits.toLocaleString());
    if (data.confidence) rows.push('Scan confidence: ' + data.confidence.toUpperCase());
    return rows;
  }

  async function runScan(rawInput) {
    const input = rawInput.trim();
    if (!input) {
      setStatus('ENTER AN EMAIL OR PHONE NUMBER', 'error');
      return;
    }
    if (scanning) return;

    scanning = true;
    setStatus('QUERYING FREE SOURCES: XPOSEDORNOT + LEAKCHECK + DISIFY...', '');
    if (scanTarget) scanTarget.textContent = input;

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input }),
      });

      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = data.detail;
        const message = Array.isArray(detail)
          ? detail.map((d) => d.msg || d).join(', ')
          : detail || 'Scan failed.';
        throw new Error(message);
      }

      setRisk(data.risk || 'LOW');
      if (scanCount) scanCount.textContent = String(data.breach_count || 0);
      if (scanDataTypes) {
        scanDataTypes.textContent = (data.data_types || []).join(', ').toUpperCase() || 'NONE';
      }

      renderList(
        scanBreaches,
        formatBreachRows(data.breaches || []),
        'No breaches found across free sources.'
      );
      renderList(scanActions, data.actions || [], 'No actions generated.');
      renderList(
        scanSources,
        (data.sources_used || []).map((s) => '✓ ' + s),
        'No sources responded.'
      );
      renderList(scanIntel, formatIntel(data), 'No extra intel available.');

      setStatus(
        'SCAN COMPLETE | FREE SOURCES: ' + (data.source || 'multi-source') + ' | NO API KEY NEEDED',
        'ok'
      );
    } catch (err) {
      setStatus(String(err.message || err).toUpperCase(), 'error');
    } finally {
      scanning = false;
    }
  }

  async function runPasswordCheck(password) {
    if (!password || password.length < 4) {
      if (pwdStatus) {
        pwdStatus.textContent = 'ENTER AT LEAST 4 CHARACTERS';
        pwdStatus.className = 'scan-status error';
      }
      return;
    }
    if (checkingPwd) return;

    checkingPwd = true;
    if (pwdStatus) {
      pwdStatus.textContent = 'CHECKING VIA HIBP PWNED PASSWORDS (FREE K-ANONYMITY)...';
      pwdStatus.className = 'scan-status';
    }

    try {
      const response = await fetch('/api/check-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || 'Password check failed.');

      const riskMap = { LOW: 'risk-low', MEDIUM: 'risk-medium', HIGH: 'risk-high' };
      if (pwdResult) {
        pwdResult.innerHTML =
          '<span class="risk-pill ' +
          (riskMap[data.risk] || 'risk-low') +
          '">' +
          (data.exposed ? 'EXPOSED' : 'SAFE') +
          '</span> ' +
          (data.message || '');
      }
      if (pwdStatus) {
        pwdStatus.textContent = data.source || 'HIBP Pwned Passwords';
        pwdStatus.className = 'scan-status ' + (data.exposed ? 'error' : 'ok');
      }
    } catch (err) {
      if (pwdStatus) {
        pwdStatus.textContent = String(err.message || err).toUpperCase();
        pwdStatus.className = 'scan-status error';
      }
    } finally {
      checkingPwd = false;
    }
  }

  if (scanForm) {
    scanForm.addEventListener('submit', (e) => {
      e.preventDefault();
      runScan(scanInput.value);
    });
  }

  if (pwdForm) {
    pwdForm.addEventListener('submit', (e) => {
      e.preventDefault();
      runPasswordCheck(pwdInput.value);
    });
  }

  scanTriggers.forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = document.getElementById('scanner-app');
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      setTimeout(() => {
        if (scanInput) scanInput.focus();
      }, 350);
    });
  });

  fetch('/api/health')
    .then((r) => r.json())
    .then((data) => {
      setStatus('SYSTEM READY — FREE MULTI-SOURCE MODE (' + (data.sources?.length || 4) + ' SOURCES)', 'ok');
    })
    .catch(() =>
      setStatus('BACKEND OFFLINE — START SERVER WITH: python -m uvicorn server:app --reload', 'error')
    );
})();
