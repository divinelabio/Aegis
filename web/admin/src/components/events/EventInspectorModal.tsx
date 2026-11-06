import React, { useState, useEffect } from 'react';
import {
  Tabs,
  TabList,
  Tab,
  TabPanels,
  TabPanel,
  StructuredListWrapper,
  StructuredListBody,
  StructuredListRow,
  StructuredListCell,
  Button,
  CodeSnippet,
  Tag,
} from '@carbon/react';
import { Close, Copy, Checkmark, Security, Launch } from '@carbon/icons-react';
import type { SecurityEventItem } from '../../types';
import { apiService } from '../../services/api';
import { COUNTRIES_MAP, countryNames } from '../../data/geoData';
import { countryCodeToFlag } from '../common/CountryBadge';
import {
  parseEventDate,
  getValidCountryCode,
  isPrivateOrLoopbackIp,
  EventScoreText,
} from './EventTableCells';

export interface EventInspectorModalProps {
  open: boolean;
  event: SecurityEventItem | null;
  onClose: () => void;
  sectionLabel?: string;
  onApplyFilter?: (field: string, value: string) => void;
  onNavigate?: (key: any) => void;
}

export const EventInspectorModal: React.FC<EventInspectorModalProps> = ({
  open,
  event,
  onClose,
  sectionLabel = 'Security Event',
  onApplyFilter,
  onNavigate,
}) => {
  const [selectedTab, setSelectedTab] = useState(0);
  const [copyFeedback, setCopyFeedback] = useState<'IP' | 'Path' | 'JSON' | 'ReqID' | null>(null);
  const [creatingExclusion, setCreatingExclusion] = useState<boolean>(false);

  useEffect(() => {
    if (open) {
      setSelectedTab(0);
    }
  }, [open, event?.id]);

  useEffect(() => {
    if (!open) return;
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.body.style.overflow = originalOverflow;
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [open, onClose]);

  if (!open || !event) return null;

  const actionLower = String(event.action || '').toLowerCase();
  const isBlocked = actionLower === 'block' || actionLower === 'drop' || event.status_code === 403;
  const isWaf =
    Boolean(event.rule_id) ||
    ['waf', 'waf_core', 'wafbasic', 'waf_rules', 'crs'].includes(String(event.section || '').toLowerCase());
  const canSuggestExclusion = isWaf || isBlocked;

  const handleCreateExclusion = async () => {
    if (!event) return;
    setCreatingExclusion(true);
    try {
      const eventId = event.id || (event as any).request_id || '';
      const ruleId = event.rule_id || '';
      const path = event.path || '';
      const ip = event.client_ip || '';

      const res = await apiService.suggestWafExclusion(eventId, {
        rule_id: ruleId,
        path,
        ip,
        reason: `Exclusion for blocked event ${ruleId ? `rule ${ruleId}` : ''} on ${path || 'request'}`.trim(),
      });

      const draftExclusion = res.exclusion || {
        id: '',
        rule_id: ruleId,
        paths: path ? [path] : [],
        ips: ip ? [ip] : [],
        reason: `Exclusion for blocked event ${ruleId ? `rule ${ruleId}` : ''}`.trim(),
        enabled: true,
      };

      try {
        sessionStorage.setItem('aegis_draft_waf_exclusion', JSON.stringify(draftExclusion));
      } catch {
      }

      onClose();
      if (typeof onNavigate === 'function') {
        onNavigate('waf-exclusions');
      }
      const targetHash = `#waf-exclusions?rule_id=${encodeURIComponent(draftExclusion.rule_id || ruleId)}&path=${encodeURIComponent(path)}`;
      window.location.hash = targetHash;
    } catch (err: any) {
      console.error('Failed to create exclusion suggestion:', err);
    } finally {
      setCreatingExclusion(false);
    }
  };

  const dateObj = parseEventDate(event.timestamp);
  const isValidDate = !Number.isNaN(dateObj.getTime());
  const formattedDate = isValidDate
    ? `${dateObj.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })} ${dateObj.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}`
    : String(event.timestamp || '—');

  const headingText =
    event.rule_name ||
    event.rule_id ||
    (event.status_code ? `HTTP ${event.status_code} Request` : 'Event Details');

  const labelText = `${sectionLabel} · ${formattedDate}`;

  const copyToClipboard = async (text: string, type: 'IP' | 'Path' | 'JSON' | 'ReqID') => {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      }
    } catch {
    }
    setCopyFeedback(type);
    setTimeout(() => setCopyFeedback(null), 2000);
  };

  const countryCode = getValidCountryCode(event.country, event.client_ip);
  const flag = countryCode ? countryCodeToFlag(countryCode) : '';
  const countryName = countryCode ? (COUNTRIES_MAP[countryCode] || countryNames[countryCode] || countryCode) : '';
  const countryDisplay = countryCode
    ? `${flag ? `${flag} ` : ''}${countryName} (${countryCode})`
    : isPrivateOrLoopbackIp(event.client_ip)
    ? 'Internal / Loopback'
    : '—';

  const hasFilterSupport = typeof onApplyFilter === 'function';

  const statusCode = event.status_code || 200;
  const statusTagType: 'red' | 'green' | 'cool-gray' =
    statusCode >= 400 ? 'red' : statusCode >= 300 ? 'cool-gray' : 'green';

  const actionText = String(event.action || '').toUpperCase();
  const actionTagType: 'red' | 'green' | 'cool-gray' =
    actionLower === 'block' || actionLower === 'drop' || actionLower === 'deny'
      ? 'red'
      : actionLower === 'allow' || actionLower === 'pass'
      ? 'green'
      : 'cool-gray';

  return (
    <>
      {/* Backdrop Scrim */}
      <div
        className="event-inspector-sidebar-overlay"
        onClick={onClose}
        aria-hidden="true"
      />

      <aside
        className="event-inspector-sidebar"
        role="dialog"
        aria-modal="true"
        aria-labelledby="event-inspector-sidebar-heading"
      >
        <div
          style={{
            padding: '16px 20px',
            borderBottom: '1px solid var(--cds-border-subtle)',
            backgroundColor: 'var(--cds-layer-01)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            gap: '12px',
            flexShrink: 0,
          }}
        >
          <div style={{ flex: 1, minWidth: 0 }}>
            <span
              style={{
                fontSize: '11px',
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                color: 'var(--cds-text-secondary)',
                display: 'block',
                marginBottom: '4px',
              }}
            >
              {labelText}
            </span>
            <h4
              id="event-inspector-sidebar-heading"
              style={{
                fontSize: '18px',
                fontWeight: 700,
                color: 'var(--cds-text-primary)',
                margin: 0,
                lineHeight: 1.3,
                wordBreak: 'break-word',
              }}
            >
              {headingText}
            </h4>
          </div>

          <Button
            kind="ghost"
            hasIconOnly
            renderIcon={Close}
            iconDescription="Close sidebar"
            onClick={onClose}
            size="sm"
            style={{
              color: 'var(--cds-icon-secondary)',
              flexShrink: 0,
            }}
          />
        </div>

        <div className="event-inspector-tabs-wrapper">
          <Tabs
            selectedIndex={selectedTab}
            onChange={({ selectedIndex }) => setSelectedTab(selectedIndex)}
          >
            <TabList aria-label="Event inspector tabs" className="event-inspector-tablist">
              <Tab>Overview</Tab>
              <Tab>Raw JSON</Tab>
            </TabList>

            <TabPanels>
              <TabPanel className="event-inspector-tabpanel">
                <div style={{ padding: '16px 20px 24px 20px' }}>
                  {/* Action & Filter Toolbar */}
                  <div
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px',
                      padding: '10px 14px',
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      borderRadius: '4px',
                      marginBottom: '16px',
                    }}
                  >
                    {hasFilterSupport && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                        <strong
                          style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            textTransform: 'uppercase',
                            letterSpacing: '0.05em',
                            color: 'var(--cds-text-secondary)',
                            marginRight: '4px',
                          }}
                        >
                          Filter:
                        </strong>
                        {event.client_ip && (
                          <Button
                            kind="ghost"
                            size="sm"
                            onClick={() => {
                              onApplyFilter('ip', event.client_ip);
                              onClose();
                            }}
                            style={{
                              height: '24px',
                              minHeight: '24px',
                              padding: '0 8px',
                              fontSize: '11px',
                              border: '1px solid var(--cds-border-subtle)',
                              borderRadius: '3px',
                              color: 'var(--cds-text-secondary)',
                              background: 'var(--cds-layer-01)',
                            }}
                          >
                            IP
                          </Button>
                        )}
                        {event.path && (
                          <Button
                            kind="ghost"
                            size="sm"
                            onClick={() => {
                              onApplyFilter('path', event.path);
                              onClose();
                            }}
                            style={{
                              height: '24px',
                              minHeight: '24px',
                              padding: '0 8px',
                              fontSize: '11px',
                              border: '1px solid var(--cds-border-subtle)',
                              borderRadius: '3px',
                              color: 'var(--cds-text-secondary)',
                              background: 'var(--cds-layer-01)',
                            }}
                          >
                            Path
                          </Button>
                        )}
                        {event.rule_id && (
                          <Button
                            kind="ghost"
                            size="sm"
                            onClick={() => {
                              onApplyFilter('rule_id', event.rule_id!);
                              onClose();
                            }}
                            style={{
                              height: '24px',
                              minHeight: '24px',
                              padding: '0 8px',
                              fontSize: '11px',
                              border: '1px solid var(--cds-border-subtle)',
                              borderRadius: '3px',
                              color: 'var(--cds-text-secondary)',
                              background: 'var(--cds-layer-01)',
                            }}
                          >
                            Rule
                          </Button>
                        )}
                        {event.action && (
                          <Button
                            kind="ghost"
                            size="sm"
                            onClick={() => {
                              onApplyFilter('action', String(event.action).toLowerCase());
                              onClose();
                            }}
                            style={{
                              height: '24px',
                              minHeight: '24px',
                              padding: '0 8px',
                              fontSize: '11px',
                              border: '1px solid var(--cds-border-subtle)',
                              borderRadius: '3px',
                              color: 'var(--cds-text-secondary)',
                              background: 'var(--cds-layer-01)',
                            }}
                          >
                            Action
                          </Button>
                        )}
                        {event.host && (
                          <Button
                            kind="ghost"
                            size="sm"
                            onClick={() => {
                              onApplyFilter('host', event.host);
                              onClose();
                            }}
                            style={{
                              height: '24px',
                              minHeight: '24px',
                              padding: '0 8px',
                              fontSize: '11px',
                              border: '1px solid var(--cds-border-subtle)',
                              borderRadius: '3px',
                              color: 'var(--cds-text-secondary)',
                              background: 'var(--cds-layer-01)',
                            }}
                          >
                            Host
                          </Button>
                        )}
                      </div>
                    )}

                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        flexWrap: 'wrap',
                        paddingTop: hasFilterSupport ? '6px' : '0',
                        borderTop: hasFilterSupport ? '1px solid var(--cds-border-subtle)' : 'none',
                      }}
                    >
                      {canSuggestExclusion && (
                        <Button
                          kind="ghost"
                          size="sm"
                          renderIcon={Security}
                          onClick={handleCreateExclusion}
                          disabled={creatingExclusion}
                          style={{
                            height: '26px',
                            minHeight: '26px',
                            padding: '0 8px',
                            fontSize: '12px',
                            border: '1px solid var(--cds-border-subtle)',
                            borderRadius: '3px',
                            color: 'var(--cds-text-primary)',
                            background: 'var(--cds-layer-01)',
                          }}
                        >
                          {creatingExclusion ? 'Drafting...' : 'Create WAF Exclusion'}
                        </Button>
                      )}
                      {event.client_ip && (
                        <Button
                          kind="ghost"
                          size="sm"
                          renderIcon={copyFeedback === 'IP' ? Checkmark : Copy}
                          onClick={() => void copyToClipboard(event.client_ip, 'IP')}
                          style={{
                            height: '26px',
                            minHeight: '26px',
                            padding: '0 8px',
                            fontSize: '12px',
                            border: '1px solid var(--cds-border-subtle)',
                            borderRadius: '3px',
                            color: 'var(--cds-text-primary)',
                            background: 'var(--cds-layer-01)',
                          }}
                        >
                          {copyFeedback === 'IP' ? 'Copied IP' : 'Copy IP'}
                        </Button>
                      )}
                      <Button
                        kind="ghost"
                        size="sm"
                        renderIcon={copyFeedback === 'JSON' ? Checkmark : Copy}
                        onClick={() => void copyToClipboard(JSON.stringify(event, null, 2), 'JSON')}
                        style={{
                          height: '26px',
                          minHeight: '26px',
                          padding: '0 8px',
                          fontSize: '12px',
                          border: '1px solid var(--cds-border-subtle)',
                          borderRadius: '3px',
                          color: 'var(--cds-text-primary)',
                          background: 'var(--cds-layer-01)',
                        }}
                      >
                        {copyFeedback === 'JSON' ? 'Copied JSON' : 'Copy JSON'}
                      </Button>
                      {onNavigate && (isBlocked || Boolean(event.rule_id)) && (
                        <Button
                          kind="ghost"
                          size="sm"
                          renderIcon={Launch}
                          onClick={() => {
                            onClose();
                            onNavigate('security-events');
                          }}
                          style={{
                            height: '26px',
                            minHeight: '26px',
                            padding: '0 8px',
                            fontSize: '12px',
                            border: '1px solid var(--cds-border-subtle)',
                            borderRadius: '3px',
                            color: 'var(--cds-text-primary)',
                            background: 'var(--cds-layer-01)',
                          }}
                        >
                          View in Security Events
                        </Button>
                      )}
                      {onNavigate && Boolean(event.section && event.section !== 'traffic') && (
                        <Button
                          kind="ghost"
                          size="sm"
                          renderIcon={Launch}
                          onClick={() => {
                            onClose();
                            onNavigate('traffic-events');
                          }}
                          style={{
                            height: '26px',
                            minHeight: '26px',
                            padding: '0 8px',
                            fontSize: '12px',
                            border: '1px solid var(--cds-border-subtle)',
                            borderRadius: '3px',
                            color: 'var(--cds-text-primary)',
                            background: 'var(--cds-layer-01)',
                          }}
                        >
                          View in Traffic Events
                        </Button>
                      )}
                    </div>
                  </div>

                  <h5
                    style={{
                      fontSize: '12px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                      color: 'var(--cds-text-secondary)',
                      marginBottom: '8px',
                    }}
                  >
                    Request Details
                  </h5>
                  <StructuredListWrapper isCondensed>
                    <StructuredListBody>
                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Host
                        </StructuredListCell>
                        <StructuredListCell style={{ fontFamily: 'var(--cds-font-mono)' }}>
                          {event.host || '—'}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Path
                        </StructuredListCell>
                        <StructuredListCell style={{ fontFamily: 'var(--cds-font-mono)', wordBreak: 'break-all' }}>
                          {event.path || '—'}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Method
                        </StructuredListCell>
                        <StructuredListCell>
                          {event.method || 'GET'}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Status
                        </StructuredListCell>
                        <StructuredListCell>
                          <Tag type={statusTagType} size="sm" style={{ margin: 0 }}>
                            {statusCode}
                          </Tag>
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Client IP
                        </StructuredListCell>
                        <StructuredListCell style={{ fontFamily: 'var(--cds-font-mono)' }}>
                          {event.client_ip || '—'}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Country
                        </StructuredListCell>
                        <StructuredListCell>
                          {countryDisplay}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Request ID
                        </StructuredListCell>
                        <StructuredListCell style={{ fontFamily: 'var(--cds-font-mono)', fontSize: '12px' }}>
                          <span style={{ marginRight: '8px', wordBreak: 'break-all' }}>{event.request_id || event.id || '—'}</span>
                          {(event.request_id || event.id) && (
                            <Button
                              kind="ghost"
                              size="sm"
                              hasIconOnly
                              renderIcon={copyFeedback === 'ReqID' ? Checkmark : Copy}
                              iconDescription="Copy Request ID"
                              onClick={() => void copyToClipboard(event.request_id || event.id || '', 'ReqID')}
                              style={{
                                height: '20px',
                                minHeight: '20px',
                                width: '20px',
                                padding: 0,
                                display: 'inline-flex',
                                verticalAlign: 'middle',
                              }}
                            />
                          )}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          User Agent
                        </StructuredListCell>
                        <StructuredListCell style={{ fontSize: '12px', wordBreak: 'break-all' }}>
                          {event.user_agent || '—'}
                        </StructuredListCell>
                      </StructuredListRow>
                    </StructuredListBody>
                  </StructuredListWrapper>

                  <h5
                    style={{
                      fontSize: '12px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                      color: 'var(--cds-text-secondary)',
                      marginTop: '20px',
                      marginBottom: '8px',
                    }}
                  >
                    Security Policy
                  </h5>
                  <StructuredListWrapper isCondensed>
                    <StructuredListBody>
                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Rule Name
                        </StructuredListCell>
                        <StructuredListCell style={{ fontWeight: 600 }}>
                          {event.rule_name || '—'}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Rule ID
                        </StructuredListCell>
                        <StructuredListCell style={{ fontFamily: 'var(--cds-font-mono)' }}>
                          {event.rule_id || '—'}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Action
                        </StructuredListCell>
                        <StructuredListCell>
                          {event.action ? (
                            <Tag type={actionTagType} size="sm" style={{ margin: 0 }}>
                              {actionText}
                            </Tag>
                          ) : (
                            '—'
                          )}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Severity
                        </StructuredListCell>
                        <StructuredListCell>
                          {event.severity ? String(event.severity).toUpperCase() : '—'}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Score
                        </StructuredListCell>
                        <StructuredListCell>
                          <EventScoreText
                            score={event.score ?? (event as any).anomaly_score ?? 0}
                            severity={event.severity || (event as any).severities?.[0]}
                          />
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Category
                        </StructuredListCell>
                        <StructuredListCell>
                          {event.category || (event as any).categories?.[0] || event.section || '—'}
                        </StructuredListCell>
                      </StructuredListRow>

                      <StructuredListRow>
                        <StructuredListCell
                          noWrap
                          style={{
                            width: '120px',
                            fontWeight: 700,
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          Matched
                        </StructuredListCell>
                        <StructuredListCell style={{ fontFamily: 'var(--cds-font-mono)', fontSize: '12px' }}>
                          {event.matched_fields && event.matched_fields.length > 0
                            ? event.matched_fields.join(', ')
                            : '—'}
                        </StructuredListCell>
                      </StructuredListRow>

                      {event.latency_ms !== undefined && (
                        <StructuredListRow>
                          <StructuredListCell
                            noWrap
                            style={{
                              width: '120px',
                              fontWeight: 700,
                              color: 'var(--cds-text-primary)',
                            }}
                          >
                            Latency
                          </StructuredListCell>
                          <StructuredListCell>
                            {event.latency_ms} ms
                          </StructuredListCell>
                        </StructuredListRow>
                      )}
                    </StructuredListBody>
                  </StructuredListWrapper>
                </div>
              </TabPanel>

              <TabPanel className="event-inspector-tabpanel">
                <div
                  style={{
                    padding: '16px 20px 24px 20px',
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    minHeight: 0,
                  }}
                >
                  <CodeSnippet
                    type="multi"
                    className="event-inspector-snippet"
                    feedback="Copied to clipboard"
                    maxCollapsedNumberOfRows={500}
                    minCollapsedNumberOfRows={40}
                  >
                    {JSON.stringify(event, null, 2)}
                  </CodeSnippet>
                </div>
              </TabPanel>
            </TabPanels>
          </Tabs>
        </div>

        <div
          style={{
            padding: '12px 20px',
            borderTop: '1px solid var(--cds-border-subtle)',
            backgroundColor: 'var(--cds-layer-01)',
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '8px',
            flexShrink: 0,
          }}
        >
          <Button kind="secondary" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </aside>
    </>
  );
};
