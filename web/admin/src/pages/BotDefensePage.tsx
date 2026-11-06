import React from 'react';
import type { NavItemKey } from '../types';
import { BotOverviewPage } from './BotOverviewPage';
import { BotManagedPage } from './BotManagedPage';
import { BotRulesPage } from './BotRulesPage';
import { BotClassificationPage } from './BotClassificationPage';
import { BotAiPage } from './BotAiPage';
import { BotExceptionsPage } from './BotExceptionsPage';

export interface BotDefensePageProps {
  initialTab?: number;
  onNavigate?: (key: NavItemKey) => void;
}

export const BotDefensePage: React.FC<BotDefensePageProps> = ({ initialTab = 0, onNavigate }) => {
  switch (initialTab) {
    case 1:
      return <BotManagedPage onNavigate={onNavigate} />;
    case 2:
      return <BotRulesPage onNavigate={onNavigate} />;
    case 3:
      return <BotClassificationPage onNavigate={onNavigate} />;
    case 4:
      return <BotAiPage onNavigate={onNavigate} />;
    case 5:
      return <BotExceptionsPage onNavigate={onNavigate} />;
    case 0:
    default:
      return <BotOverviewPage onNavigate={onNavigate} />;
  }
};

export default BotDefensePage;
