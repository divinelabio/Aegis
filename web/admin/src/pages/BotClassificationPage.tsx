import React, { useState, useEffect, useMemo } from 'react';
import {
  Tile,
  Layer,
  Search,
  Select,
  SelectItem,
  Button,
  Tag,
  InlineNotification,
} from '@carbon/react';
import { Tag as TagIcon, Checkmark, Close } from '@carbon/icons-react';
import {
  PageHeader,
  SectionCard,
  StatusToggle,
  SaveActionBar,
} from '../components/common';
import { BotBrandLogo } from '../components/bot/BotBrandLogo';
import { apiService } from '../services/api';
import type { AntibotFullConfig, NavItemKey } from '../types';

interface BotClassificationPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

export interface VerifiedBotItem {
  name: string;
  category: string;
  organization: string;
}

const VERIFIED_BOTS: VerifiedBotItem[] = [
  { name: 'Googlebot', category: 'Search Engine', organization: 'Google' },
  { name: 'Bingbot', category: 'Search Engine', organization: 'Microsoft' },
  { name: 'Applebot', category: 'Search & Siri', organization: 'Apple' },
  { name: 'DuckDuckGo', category: 'Search Engine', organization: 'DuckDuckGo' },
  { name: 'Baiduspider', category: 'Search Engine', organization: 'Baidu' },
  { name: 'YandexBot', category: 'Search Engine', organization: 'Yandex' },
  { name: 'Twitterbot', category: 'Social Media', organization: 'X / Twitter' },
  { name: 'WhatsApp', category: 'Messaging', organization: 'Meta' },
  { name: 'Telegram', category: 'Messaging', organization: 'Telegram' },
  { name: 'LinkedInBot', category: 'Professional', organization: 'LinkedIn' },
  { name: 'Pinterestbot', category: 'Social Media', organization: 'Pinterest' },
  { name: 'Amazonbot', category: 'E-commerce', organization: 'Amazon' },
  { name: 'Slackbot', category: 'Collaboration', organization: 'Slack' },
  { name: 'ZoomBot', category: 'Conferencing', organization: 'Zoom' },
  { name: 'Zapier', category: 'Automation', organization: 'Zapier' },
  { name: 'Stripe', category: 'Payment Gateway', organization: 'Stripe' },
  { name: 'PayPal', category: 'Payment Services', organization: 'PayPal' },
  { name: 'Datadog Agent', category: 'Cloud Monitoring', organization: 'Datadog' },
  { name: 'UptimeRobot', category: 'Uptime Monitor', organization: 'UptimeRobot' },
  { name: 'Pingdom', category: 'Synthetic Monitor', organization: 'SolarWinds' },
  { name: 'AhrefsBot', category: 'SEO Intelligence', organization: 'Ahrefs' },
  { name: 'SemrushBot', category: 'SEO Intelligence', organization: 'Semrush' },
  { name: 'DotBot', category: 'SEO Crawler', organization: 'Moz' },
  { name: 'MJ12bot', category: 'SEO Crawler', organization: 'Majestic' },
  { name: 'Exabot', category: 'Search Engine', organization: 'Exalead' },
  { name: 'SeznamBot', category: 'Search Engine', organization: 'Seznam' },
  { name: 'CocCocBot', category: 'Search Engine', organization: 'Cốc Cốc' },
  { name: 'PetalBot', category: 'Search Engine', organization: 'Huawei' },
  { name: 'MojeekBot', category: 'Search Engine', organization: 'Mojeek' },
  { name: 'TurnitinBot', category: 'Academic Integrity', organization: 'Turnitin' },
  { name: 'Archive.org_bot', category: 'Digital Archive', organization: 'Internet Archive' },
  { name: 'OracleBot', category: 'Enterprise Cloud', organization: 'Oracle' },
  { name: 'Salesforce', category: 'CRM & Marketing', organization: 'Salesforce' },
  { name: 'GrapeshotCrawler', category: 'Brand Safety', organization: 'Oracle' },
];

export const BotClassificationPage: React.FC<BotClassificationPageProps> = () => {
  const [_loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [isDirty, setIsDirty] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [blockBadBots, setBlockBadBots] = useState<boolean>(true);
  const [verifySearchEngines, setVerifySearchEngines] = useState<boolean>(true);
  const [allowGoodBots, setAllowGoodBots] = useState<boolean>(true);
  const [treatUnknownAsBot, setTreatUnknownAsBot] = useState<boolean>(false);
  const [goodBotRules, setGoodBotRules] = useState<Record<string, { action: string; verify_dns?: boolean }>>({});
  const [botSearch, setBotSearch] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  const [initialConfig, setInitialConfig] = useState<AntibotFullConfig | null>(null);

  const categories = useMemo(() => {
    const set = new Set<string>();
    VERIFIED_BOTS.forEach((b) => set.add(b.category));
    return Array.from(set).sort();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const cfg = await apiService.getAntibotConfig();
      if (cfg) {
        setInitialConfig(cfg);
        const cl = cfg.classification || {};
        setBlockBadBots(cl.block_bad_bots !== false);
        setVerifySearchEngines(cl.verify_search_engines !== false);
        setAllowGoodBots(cl.allow_good_bots !== false);
        setTreatUnknownAsBot(Boolean(cl.treat_unknown_as_bot));
        setGoodBotRules(cl.good_bot_rules || {});
      }
      setIsDirty(false);
    } catch {
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const markDirty = () => setIsDirty(true);

  const filteredBots = useMemo(() => {
    const q = botSearch.trim().toLowerCase();
    return VERIFIED_BOTS.filter((b) => {
      const matchesSearch =
        !q ||
        b.name.toLowerCase().includes(q) ||
        b.category.toLowerCase().includes(q) ||
        b.organization.toLowerCase().includes(q);

      const matchesCat = selectedCategory === 'all' || b.category === selectedCategory;

      return matchesSearch && matchesCat;
    });
  }, [botSearch, selectedCategory]);

  const activeGoodBotsCount = useMemo(() => {
    if (!allowGoodBots) return 0;
    return VERIFIED_BOTS.filter((b) => goodBotRules[b.name]?.action !== 'disabled').length;
  }, [allowGoodBots, goodBotRules]);

  const handleToggleBot = (botName: string, active: boolean) => {
    setGoodBotRules((prev) => ({
      ...prev,
      [botName]: {
        action: active ? 'allow' : 'disabled',
        verify_dns: true,
      },
    }));
    markDirty();
  };

  const handleBulkToggle = (active: boolean) => {
    const next: Record<string, { action: string; verify_dns?: boolean }> = {};
    VERIFIED_BOTS.forEach((bot) => {
      next[bot.name] = { action: active ? 'allow' : 'disabled', verify_dns: true };
    });
    setGoodBotRules(next);
    markDirty();
    setNotification({
      kind: 'info',
      message: `${active ? 'Allowed' : 'Disabled'} all ${VERIFIED_BOTS.length} verified crawlers. Save to deploy changes.`,
    });
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const payload: Partial<AntibotFullConfig> = {
        ...(initialConfig || {}),
        classification: {
          block_bad_bots: blockBadBots,
          verify_search_engines: verifySearchEngines,
          allow_good_bots: allowGoodBots,
          treat_unknown_as_bot: treatUnknownAsBot,
          good_bot_rules: goodBotRules,
        },
      };

      const res = await apiService.saveAntibotConfig(payload);
      if (res && res.success === false) {
        setNotification({ kind: 'error', message: res.error || 'Failed to save settings.' });
        return;
      }
      setInitialConfig({ ...(initialConfig || {}), ...payload } as AntibotFullConfig);
      setIsDirty(false);
      setNotification({ kind: 'success', message: 'Bot classification settings saved successfully.' });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Failed to save settings.' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ padding: '32px 32px 100px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Bot defense"
        title="Classification"
        icon={TagIcon}
      />

      {notification && (
        <div style={{ marginBottom: '24px' }}>
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      <SectionCard
        title="Classification Policy"
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
          <StatusToggle
            id="toggle-block-bad"
            label="Block Malicious Bots"
            toggled={blockBadBots}
            onToggle={(c) => { setBlockBadBots(c); markDirty(); }}
            description="Block known vulnerability scanners and malicious scrapers."
            size="md"
          />
          <StatusToggle
            id="toggle-verify-dns"
            label="FCrDNS Verification"
            toggled={verifySearchEngines}
            onToggle={(c) => { setVerifySearchEngines(c); markDirty(); }}
            description="Verify search engine authenticity using Forward-Confirmed Reverse DNS."
            size="md"
          />
          <StatusToggle
            id="toggle-allow-good"
            label="Allow Verified Bots"
            toggled={allowGoodBots}
            onToggle={(c) => { setAllowGoodBots(c); markDirty(); }}
            description="Bypass protection for verified search engines and monitoring services."
            size="md"
          />
          <StatusToggle
            id="toggle-treat-unknown"
            label="Treat Unknown User-Agents as Suspicious"
            toggled={treatUnknownAsBot}
            onToggle={(c) => { setTreatUnknownAsBot(c); markDirty(); }}
            description="Increase bot threat score for empty or non-standard User-Agent strings."
            size="md"
          />
        </div>
      </SectionCard>

      <SectionCard
        title="Verified Bots Directory"
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Tag type="blue" size="md">
              {activeGoodBotsCount} / {VERIFIED_BOTS.length} Active
            </Tag>
            <Button
              kind="ghost"
              size="sm"
              renderIcon={Checkmark}
              onClick={() => handleBulkToggle(true)}
              style={{ borderRadius: 0 }}
            >
              Allow All
            </Button>
            <Button
              kind="ghost"
              size="sm"
              renderIcon={Close}
              onClick={() => handleBulkToggle(false)}
              style={{ borderRadius: 0 }}
            >
              Disable All
            </Button>
          </div>
        }
      >
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '240px' }}>
            <Search
              id="search-bots"
              labelText="Search recognized crawlers"
              placeholder="Search crawlers, organizations, or categories..."
              value={botSearch}
              onChange={(e) => setBotSearch(e.target.value)}
              size="md"
            />
          </div>
          <div style={{ width: '220px' }}>
            <Select
              id="filter-bot-category"
              labelText="Filter by Category"
              hideLabel
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              size="md"
            >
              <SelectItem value="all" text="All Categories" />
              {categories.map((cat) => (
                <SelectItem key={cat} value={cat} text={cat} />
              ))}
            </Select>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(310px, 1fr))', gap: '12px' }}>
          {filteredBots.map((bot) => {
            const isDisabled = goodBotRules[bot.name]?.action === 'disabled';
            const isBotActive = allowGoodBots && !isDisabled;

            return (
              <Layer key={bot.name}>
                <Tile
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '12px 16px',
                    border: '1px solid var(--cds-border-subtle)',
                    borderRadius: 0,
                    background: 'var(--cds-layer-01)',
                    gap: '12px',
                    boxSizing: 'border-box',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0, flex: 1 }}>
                    <BotBrandLogo botName={bot.name} category={bot.organization} size={36} />
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div
                        style={{
                          fontWeight: 600,
                          fontSize: '14px',
                          color: 'var(--cds-text-primary)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          lineHeight: 1.2,
                        }}
                        title={bot.name}
                      >
                        {bot.name}
                      </div>
                      <div
                        style={{
                          fontSize: '12px',
                          color: 'var(--cds-text-secondary)',
                          marginTop: '2px',
                          overflow: 'hidden',
                          whiteSpace: 'nowrap',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {bot.category}
                      </div>
                    </div>
                  </div>
                  <StatusToggle
                    id={`toggle-bot-${bot.name}`}
                    toggled={isBotActive}
                    disabled={!allowGoodBots}
                    onToggle={(c) => handleToggleBot(bot.name, c)}
                    size="sm"
                    hideLabel
                    ariaLabel={`Toggle ${bot.name}`}
                  />
                </Tile>
              </Layer>
            );
          })}
        </div>
      </SectionCard>

      <SaveActionBar
        isDirty={isDirty}
        isSaving={saving}
        onReset={loadData}
        onSave={handleSave}
      />
    </div>
  );
};

export default BotClassificationPage;
