import React, { useState, useEffect, useMemo } from 'react';
import {
  Tile,
  Layer,
  Button,
  Tag,
  Search,
  Select,
  SelectItem,
  InlineNotification,
} from '@carbon/react';
import { Bot, Checkmark, Security, Misuse } from '@carbon/icons-react';
import {
  PageHeader,
  SectionCard,
  SaveActionBar,
} from '../components/common';
import { BotBrandLogo } from '../components/bot/BotBrandLogo';
import { apiService } from '../services/api';
import type { AntibotFullConfig, NavItemKey } from '../types';

interface BotAiPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

type CrawlerAction = 'allow' | 'challenge' | 'block';

interface AICrawler {
  name: string;
  category: string;
  description: string;
}

const AI_BOTS: AICrawler[] = [
  { name: 'GPTBot', category: 'OpenAI', description: 'Web crawler used to train OpenAI generative models.' },
  { name: 'ChatGPT-User', category: 'OpenAI', description: 'On-demand browsing fetcher for live ChatGPT user queries.' },
  { name: 'Claude-Web', category: 'Anthropic', description: 'Anthropic crawler for Claude live web retrieval.' },
  { name: 'Anthropic-AI', category: 'Anthropic', description: 'Batch model training crawler for Anthropic Claude.' },
  { name: 'Google-Extended', category: 'Google', description: 'Controls whether site content trains Gemini and Vertex AI.' },
  { name: 'Applebot', category: 'Apple', description: 'Applebot web indexer and Apple Intelligence training crawler.' },
  { name: 'PerplexityBot', category: 'Perplexity', description: 'Real-time conversational search crawler for Perplexity AI.' },
  { name: 'CCBot', category: 'Common Crawl', description: 'Nonprofit web crawl dataset frequently used by open source LLMs.' },
  { name: 'Bytespider', category: 'ByteDance', description: 'Automated content aggregator for ByteDance and Doubao AI.' },
  { name: 'FacebookBot', category: 'Meta', description: 'Meta web crawler powering Llama and Meta AI retrieval.' },
  { name: 'Amazonbot', category: 'Amazon', description: 'Amazon crawler for Alexa web indexing and Bedrock AI training.' },
  { name: 'Omgilibot', category: 'Webz.io', description: 'Commercial web scraping bot providing syndicated enterprise feeds.' },
  { name: 'Diffbot', category: 'Diffbot', description: 'Knowledge graph extraction and structured scraping bot.' },
  { name: 'Cohere', category: 'Cohere', description: 'Enterprise training crawler for Cohere Command and Embed models.' },
  { name: 'YouBot', category: 'You.com', description: 'Search bot and conversational summarizer for You.com.' },
];

export const BotAiPage: React.FC<BotAiPageProps> = () => {
  const [_loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [isDirty, setIsDirty] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [aiEnabled, setAiEnabled] = useState<boolean>(true);
  const [aiRules, setAiRules] = useState<Record<string, { action: string; verify_dns?: boolean }>>({});
  const [aiSearch, setAiSearch] = useState<string>('');
  const [aiCategoryFilter, setAiCategoryFilter] = useState<string>('all');
  const [initialConfig, setInitialConfig] = useState<AntibotFullConfig | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const cfg = await apiService.getAntibotConfig();
      if (cfg) {
        setInitialConfig(cfg);
        const rawAi = cfg.ai_crawlers;
        setAiEnabled(rawAi?.enabled !== false);
        const existingRules =
          rawAi && typeof rawAi === 'object' && 'rules' in rawAi && rawAi.rules
            ? rawAi.rules
            : (rawAi as Record<string, { action: string; verify_dns?: boolean }>) || {};

        const populated: Record<string, { action: string; verify_dns?: boolean }> = {};
        AI_BOTS.forEach((bot) => {
          const r = existingRules[bot.name];
          const act = r?.action || 'allow';
          populated[bot.name] = {
            action: ['allow', 'challenge', 'block'].includes(act) ? act : 'allow',
            verify_dns: r?.verify_dns !== false,
          };
        });
        setAiRules(populated);
      } else {
        setAiEnabled(true);
        const fallback: Record<string, { action: string; verify_dns?: boolean }> = {};
        AI_BOTS.forEach((bot) => {
          fallback[bot.name] = { action: 'allow', verify_dns: true };
        });
        setAiRules(fallback);
      }
      setIsDirty(false);
    } catch {
      setAiEnabled(true);
      const fallback: Record<string, { action: string; verify_dns?: boolean }> = {};
      AI_BOTS.forEach((bot) => {
        fallback[bot.name] = { action: 'allow', verify_dns: true };
      });
      setAiRules(fallback);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const markDirty = () => setIsDirty(true);

  const categories = useMemo(() => {
    return Array.from(new Set(AI_BOTS.map((bot) => bot.category))).sort();
  }, []);

  const filteredAiBots = useMemo(() => {
    const q = aiSearch.trim().toLowerCase();
    return AI_BOTS.filter((bot) => {
      if (aiCategoryFilter !== 'all' && bot.category.toLowerCase() !== aiCategoryFilter.toLowerCase()) {
        return false;
      }
      if (q && !bot.name.toLowerCase().includes(q) && !bot.category.toLowerCase().includes(q)) {
        return false;
      }
      return true;
    });
  }, [aiSearch, aiCategoryFilter]);

  const setAiBotAction = (botName: string, action: CrawlerAction) => {
    setAiRules((prev) => ({
      ...prev,
      [botName]: { action, verify_dns: true },
    }));
    markDirty();
  };

  const handleBulkAiAction = (action: CrawlerAction) => {
    const next: Record<string, { action: string; verify_dns?: boolean }> = {};
    AI_BOTS.forEach((bot) => {
      next[bot.name] = { action, verify_dns: true };
    });
    setAiRules(next);
    markDirty();
    setNotification({
      kind: 'info',
      message: `Set all AI crawler policies to ${action.toUpperCase()}. Remember to save changes.`,
    });
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const payload: Partial<AntibotFullConfig> = {
        ...(initialConfig || {}),
        ai_crawlers: {
          enabled: aiEnabled,
          rules: aiRules,
        },
      };

      const res = await apiService.saveAntibotConfig(payload);
      if (res && res.success === false) {
        setNotification({ kind: 'error', message: res.error || 'Failed to save policies.' });
        return;
      }
      setInitialConfig({ ...(initialConfig || {}), ...payload } as AntibotFullConfig);
      setIsDirty(false);
      setNotification({ kind: 'success', message: 'AI crawler policies saved successfully.' });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Failed to save policies.' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ padding: '32px 32px 100px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Bot defense"
        title="AI crawlers"
        icon={Bot}
        action={
          <div style={{ display: 'flex', gap: '8px' }}>
            <Button
              kind="secondary"
              size="md"
              renderIcon={Checkmark}
              onClick={() => handleBulkAiAction('allow')}
            >
              Allow All
            </Button>
            <Button
              kind="secondary"
              size="md"
              renderIcon={Security}
              onClick={() => handleBulkAiAction('challenge')}
            >
              Challenge All
            </Button>
            <Button
              kind="danger"
              size="md"
              renderIcon={Misuse}
              onClick={() => handleBulkAiAction('block')}
            >
              Block All
            </Button>
          </div>
        }
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
        title="AI Crawlers & Extractors"
      >
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '240px' }}>
            <Search
              id="search-ai"
              labelText="Search AI crawler or organization"
              placeholder="Search by crawler or organization..."
              value={aiSearch}
              onChange={(e) => setAiSearch(e.target.value)}
              size="md"
            />
          </div>
          <div style={{ width: '220px' }}>
            <Select
              id="filter-org"
              labelText="Filter by Organization"
              hideLabel
              value={aiCategoryFilter}
              onChange={(e) => setAiCategoryFilter(e.target.value)}
              size="md"
            >
              <SelectItem value="all" text="All Organizations" />
              {categories.map((cat) => (
                <SelectItem key={cat} value={cat} text={cat} />
              ))}
            </Select>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '16px' }}>
          {filteredAiBots.map((bot) => {
            const currentAction = (aiRules[bot.name]?.action || 'allow') as CrawlerAction;

            return (
              <Layer key={bot.name}>
                <Tile
                  style={{
                    padding: '20px',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    height: '100%',
                    borderRadius: 0,
                    border: '1px solid var(--cds-border-subtle)',
                    background: 'var(--cds-layer-01)',
                    boxSizing: 'border-box',
                  }}
                >
                  <div>
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: '12px',
                        marginBottom: '12px',
                      }}
                    >
                      <BotBrandLogo botName={bot.name} category={bot.category} size={36} />
                      <div
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          alignItems: 'flex-start',
                          gap: '4px',
                          minWidth: 0,
                        }}
                      >
                        <div
                          style={{
                            fontWeight: 600,
                            fontSize: '15px',
                            color: 'var(--cds-text-primary)',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            lineHeight: 1.2,
                          }}
                        >
                          {bot.name}
                        </div>
                        <Tag type="cool-gray" size="sm" style={{ margin: 0 }}>
                          {bot.category}
                        </Tag>
                      </div>
                    </div>

                    <div
                      style={{
                        fontSize: '13px',
                        color: 'var(--cds-text-secondary)',
                        marginBottom: '20px',
                        lineHeight: '1.4',
                        minHeight: '36px',
                      }}
                    >
                      {bot.description}
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '8px', width: '100%', marginTop: 'auto' }}>
                    {(['allow', 'challenge', 'block'] as const).map((act) => {
                      const isSelected = currentAction === act;
                      const btnKind = isSelected
                        ? act === 'block'
                          ? 'danger'
                          : act === 'challenge'
                          ? 'secondary'
                          : 'primary'
                        : 'ghost';

                      return (
                        <Button
                          key={act}
                          kind={btnKind}
                          size="sm"
                          style={{
                            flex: 1,
                            justifyContent: 'center',
                            textAlign: 'center',
                            paddingLeft: 0,
                            paddingRight: 0,
                            textTransform: 'capitalize',
                            borderRadius: 0,
                            border: isSelected ? undefined : '1px solid var(--cds-border-subtle)',
                          }}
                          onClick={() => setAiBotAction(bot.name, act)}
                        >
                          <span style={{ width: '100%', textAlign: 'center' }}>{act}</span>
                        </Button>
                      );
                    })}
                  </div>
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

export default BotAiPage;
