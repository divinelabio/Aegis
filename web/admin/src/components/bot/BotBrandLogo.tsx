import React from 'react';

export interface BotBrandLogoProps {
  botName: string;
  category?: string;
  size?: number;
  className?: string;
  style?: React.CSSProperties;
}

interface BrandDefinition {
  bg: string;
  border?: string;
  renderIcon: (iconSize: number) => React.ReactNode;
}

// Canonical vector logos for AI Crawlers and Verified Good Bots
const BRAND_DEFINITIONS: Record<string, BrandDefinition> = {
  GPTBot: {
    bg: 'linear-gradient(135deg, #10a37f 0%, #0d8a6a 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M22.28 9.82a5.98 5.98 0 0 0-.52-4.91 6.05 6.05 0 0 0-6.51-2.9 6.06 6.06 0 0 0-4.98 2.17 5.98 5.98 0 0 0-4 2.9 6.05 6.05 0 0 0 .74 7.1 5.98 5.98 0 0 0 .51 4.91 6.05 6.05 0 0 0 6.51 2.9 5.98 5.98 0 0 0 4.28 1.91 6.05 6.05 0 0 0 5.77-4.21 5.99 5.99 0 0 0 4-2.9 6.05 6.05 0 0 0-.75-7.07zm-9.02 12.61a4.48 4.48 0 0 1-2.88-1.04l.14-.08 4.78-2.76c.24-.14.39-.4.39-.68V11.13l2.02 1.17c.02.01.04.03.04.05v5.58a4.5 4.5 0 0 1-4.49 4.5zm-9.66-4.13a4.47 4.47 0 0 1-.53-3.01l.14.08 4.78 2.76a.77.77 0 0 0 .78 0l5.84-3.37v2.33c0 .03-.01.05-.03.06L9.74 19.95a4.5 4.5 0 0 1-6.14-1.65zm-1.26-6.41a4.48 4.48 0 0 1 2.37-1.97v5.68c0 .28.15.54.39.68l5.81 3.35-2.02 1.17a.08.08 0 0 1-.07 0l-4.83-2.79a4.5 4.5 0 0 1-1.65-6.12zm16.6 3.86l-5.84-3.37 2.02-1.16a.08.08 0 0 1 .07 0l4.83 2.79a4.49 4.49 0 0 1-.68 8.1v-5.68c0-.27-.15-.53-.4-.68zm2.01-3.02l-.14-.09-4.77-2.78a.78.78 0 0 0-.79 0L9.41 9.23V6.9a.07.07 0 0 1 .03-.06l4.83-2.79a4.5 4.5 0 0 1 6.68 4.66zM8.31 12.86l-2.02-1.16a.08.08 0 0 1-.04-.06V6.07a4.5 4.5 0 0 1 7.38-3.45l-.14.08-4.78 2.76a.8.8 0 0 0-.4.68v6.72zm1.14-1.56l2.6-1.5 2.6 1.5v3l-2.6 1.5-2.6-1.5z" />
      </svg>
    ),
  },
  'ChatGPT-User': {
    bg: 'linear-gradient(135deg, #10a37f 0%, #0a7056 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M22.28 9.82a5.98 5.98 0 0 0-.52-4.91 6.05 6.05 0 0 0-6.51-2.9 6.06 6.06 0 0 0-4.98 2.17 5.98 5.98 0 0 0-4 2.9 6.05 6.05 0 0 0 .74 7.1 5.98 5.98 0 0 0 .51 4.91 6.05 6.05 0 0 0 6.51 2.9 5.98 5.98 0 0 0 4.28 1.91 6.05 6.05 0 0 0 5.77-4.21 5.99 5.99 0 0 0 4-2.9 6.05 6.05 0 0 0-.75-7.07zm-9.02 12.61a4.48 4.48 0 0 1-2.88-1.04l.14-.08 4.78-2.76c.24-.14.39-.4.39-.68V11.13l2.02 1.17c.02.01.04.03.04.05v5.58a4.5 4.5 0 0 1-4.49 4.5zm-9.66-4.13a4.47 4.47 0 0 1-.53-3.01l.14.08 4.78 2.76a.77.77 0 0 0 .78 0l5.84-3.37v2.33c0 .03-.01.05-.03.06L9.74 19.95a4.5 4.5 0 0 1-6.14-1.65zm-1.26-6.41a4.48 4.48 0 0 1 2.37-1.97v5.68c0 .28.15.54.39.68l5.81 3.35-2.02 1.17a.08.08 0 0 1-.07 0l-4.83-2.79a4.5 4.5 0 0 1-1.65-6.12zm16.6 3.86l-5.84-3.37 2.02-1.16a.08.08 0 0 1 .07 0l4.83 2.79a4.49 4.49 0 0 1-.68 8.1v-5.68c0-.27-.15-.53-.4-.68zm2.01-3.02l-.14-.09-4.77-2.78a.78.78 0 0 0-.79 0L9.41 9.23V6.9a.07.07 0 0 1 .03-.06l4.83-2.79a4.5 4.5 0 0 1 6.68 4.66zM8.31 12.86l-2.02-1.16a.08.08 0 0 1-.04-.06V6.07a4.5 4.5 0 0 1 7.38-3.45l-.14.08-4.78 2.76a.8.8 0 0 0-.4.68v6.72zm1.14-1.56l2.6-1.5 2.6 1.5v3l-2.6 1.5-2.6-1.5z" />
      </svg>
    ),
  },
  'Claude-Web': {
    bg: 'linear-gradient(135deg, #d97757 0%, #ba5d3f 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 1.5a1.2 1.2 0 0 1 1.2 1.2v2.8a1.2 1.2 0 0 1-2.4 0V2.7A1.2 1.2 0 0 1 12 1.5zm7.425 3.075a1.2 1.2 0 0 1 0 1.697l-1.98 1.98a1.2 1.2 0 1 1-1.697-1.697l1.98-1.98a1.2 1.2 0 0 1 1.697 0zM22.5 12a1.2 1.2 0 0 1-1.2 1.2h-2.8a1.2 1.2 0 0 1 0-2.4h2.8a1.2 1.2 0 0 1 1.2 1.2zm-3.075 7.425a1.2 1.2 0 0 1-1.697 0l-1.98-1.98a1.2 1.2 0 0 1 1.697-1.697l1.98 1.98a1.2 1.2 0 0 1 0 1.697zM12 22.5a1.2 1.2 0 0 1-1.2-1.2v-2.8a1.2 1.2 0 0 1 2.4 0v2.8a1.2 1.2 0 0 1-1.2 1.2zm-7.425-3.075a1.2 1.2 0 0 1 0-1.697l1.98-1.98a1.2 1.2 0 1 1 1.697 1.697l-1.98 1.98a1.2 1.2 0 0 1-1.697 0zM1.5 12a1.2 1.2 0 0 1 1.2-1.2h2.8a1.2 1.2 0 0 1 0 2.4H2.7A1.2 1.2 0 0 1 1.5 12zm3.075-7.425a1.2 1.2 0 0 1 1.697 0l1.98 1.98a1.2 1.2 0 1 1-1.697 1.697l-1.98-1.98a1.2 1.2 0 0 1 0-1.697zM12 7.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9z" />
      </svg>
    ),
  },
  'Anthropic-AI': {
    bg: 'linear-gradient(135deg, #d97757 0%, #ba5d3f 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M17.472 4.137 12.012 18.72l-2.85-.79 1.432-3.832H4.665l-1.432 3.832L.383 17.14 5.843 2.557h2.85l3.823 10.225 1.432-3.832h-3.418l.836-2.235h4.63l.635-1.701 2.85.79.636-1.701z" />
      </svg>
    ),
  },
  'Google-Extended': {
    bg: '#ffffff',
    border: '1px solid rgba(0, 0, 0, 0.14)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} aria-hidden="true">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" fill="#FBBC05" />
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" fill="#EA4335" />
      </svg>
    ),
  },
  Applebot: {
    bg: 'linear-gradient(135deg, #3a3a3c 0%, #1c1c1e 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83zM15.97 6.37c.62-.75 1.04-1.8 1.01-2.87-.96.04-2.12.64-2.8 1.44-.6.69-1.12 1.77-.98 2.82 1.07.08 2.15-.55 2.77-1.39z" />
      </svg>
    ),
  },
  PerplexityBot: {
    bg: 'linear-gradient(135deg, #1fb8cd 0%, #0d8b9d 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2a1 1 0 0 0-1 1v4.062L7.545 4.22a1 1 0 0 0-1.414 1.414L9.06 8.562H5a1 1 0 1 0 0 2h4.062L6.13 13.49a1 1 0 1 0 1.414 1.414L11 11.97V16a1 1 0 1 0 2 0v-4.03l3.456 2.903a1 1 0 0 0 1.414-1.414L14.94 10.562H19a1 1 0 1 0 0-2h-4.062l2.93-2.93a1 1 0 0 0-1.414-1.414L13 7.062V3a1 1 0 0 0-1-1z" />
      </svg>
    ),
  },
  CCBot: {
    bg: 'linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1.8 14.5c-2.49 0-4.5-2.01-4.5-4.5s2.01-4.5 4.5-4.5c1.45 0 2.73.69 3.55 1.76l-1.46 1.14c-.52-.63-1.28-1.03-2.09-1.03-1.46 0-2.65 1.19-2.65 2.63s1.19 2.63 2.65 2.63c.81 0 1.57-.4 2.09-1.03l1.46 1.14c-.82 1.07-2.1 1.76-3.55 1.76zm4.8 0c-2.49 0-4.5-2.01-4.5-4.5s2.01-4.5 4.5-4.5c1.45 0 2.73.69 3.55 1.76l-1.46 1.14c-.52-.63-1.28-1.03-2.09-1.03-1.46 0-2.65 1.19-2.65 2.63s1.19 2.63 2.65 2.63c.81 0 1.57-.4 2.09-1.03l1.46 1.14c-.82 1.07-2.1 1.76-3.55 1.76z" />
      </svg>
    ),
  },
  Bytespider: {
    bg: 'linear-gradient(135deg, #325ab4 0%, #1ea1c4 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M4.5 7.2a1.2 1.2 0 0 1 1.8-1.04l4.5 2.6a1.2 1.2 0 0 1 .6 1.04v2.7a1.2 1.2 0 0 1-1.8 1.04l-4.5-2.6a1.2 1.2 0 0 1-.6-1.04V7.2zm8.4 4.8a1.2 1.2 0 0 1 1.8-1.04l4.5 2.6a1.2 1.2 0 0 1 .6 1.04v2.7a1.2 1.2 0 0 1-1.8 1.04l-4.5-2.6a1.2 1.2 0 0 1-.6-1.04V12zm-8.4 2.4a1.2 1.2 0 0 1 1.8-1.04l4.5 2.6a1.2 1.2 0 0 1 .6 1.04v2.7a1.2 1.2 0 0 1-1.8 1.04l-4.5-2.6a1.2 1.2 0 0 1-.6-1.04v-2.7zm8.4-9.6a1.2 1.2 0 0 1 1.8-1.04l4.5 2.6a1.2 1.2 0 0 1 .6 1.04v2.7a1.2 1.2 0 0 1-1.8 1.04l-4.5-2.6a1.2 1.2 0 0 1-.6-1.04V4.8z" />
      </svg>
    ),
  },
  FacebookBot: {
    bg: 'linear-gradient(135deg, #0081fb 0%, #0064e0 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12.001 8.077c-1.97 0-3.69 1.109-4.834 2.618C5.816 8.924 4.148 8.077 2.378 8.077 1.065 8.077 0 9.142 0 10.455c0 1.62.907 3.018 2.053 4.295 1.487 1.657 3.328 3.12 5.093 4.143a4.015 4.015 0 0 0 4.854 0c1.765-1.023 3.606-2.486 5.093-4.143 1.146-1.277 2.053-2.675 2.053-4.295 0-1.313-1.065-2.378-2.378-2.378-1.77 0-3.438.847-4.789 2.618-1.144-1.509-2.864-2.618-4.834-2.618zm-4.3 3.513c.96 0 1.905.795 2.597 1.874-.933 1.054-2.021 2.091-3.155 2.835-1.21-.77-2.29-1.802-3.14-2.835.692-1.079 1.637-1.874 2.598-1.874zm8.6 0c.961 0 1.906.795 2.598 1.874-.85 1.033-1.93 2.065-3.14 2.835-1.134-.744-2.222-1.781-3.155-2.835.692-1.079 1.637-1.874 2.597-1.874z" />
      </svg>
    ),
  },
  Amazonbot: {
    bg: 'linear-gradient(135deg, #ff9900 0%, #e68a00 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M.045 18.02c.072-.116.187-.124.348-.022 3.636 2.11 7.594 3.166 11.87 3.166 2.852 0 5.668-.533 8.447-1.595.47-.189.873-.395 1.21-.618.226-.15.44-.15.64.01.195.155.234.37.115.63-.285.63-.853 1.14-1.7 1.53-2.53 1.16-5.335 1.74-8.415 1.74-4.61 0-8.78-1.24-12.51-3.72-.247-.166-.327-.4-.24-.685l.045-.116.19-.32z" />
      </svg>
    ),
  },
  Omgilibot: {
    bg: 'linear-gradient(135deg, #8b5cf6 0%, #6d28d9 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm1 14.93V15a1 1 0 0 0-2 0v1.93A8 8 0 0 1 4.07 13H6a1 1 0 0 0 0-2H4.07A8 8 0 0 1 11 4.07V6a1 1 0 0 0 2 0V4.07A8 8 0 0 1 19.93 11H18a1 1 0 0 0 0 2h1.93A8 8 0 0 1 13 16.93zM12 8a4 4 0 1 0 4 4 4 4 0 0 0-4-4zm0 6a2 2 0 1 1 2-2 2 2 0 0 1-2 2z" />
      </svg>
    ),
  },
  Diffbot: {
    bg: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2.5 4 7.1v9.8l8 4.6 8-4.6V7.1L12 2.5zm0 2.3 5.9 3.4-5.9 3.4L6.1 8.2 12 4.8zm-6.5 4.8 5.5 3.2v6.4l-5.5-3.2V9.6zm13 6.4-5.5 3.2v-6.4l5.5-3.2v6.4z" />
      </svg>
    ),
  },
  Cohere: {
    bg: 'linear-gradient(135deg, #e06d53 0%, #b8432a 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M7.4 3.7c3.9-1.4 8.7-.3 11.4 2.8 2.6 3.1 3 8 .9 11.4-2.1 3.4-6.4 5.3-10.4 4.6-4.1-.7-7.3-4.2-7.3-8.4 0-4.4 2.8-8.8 5.4-10.4z" />
        <circle cx="12" cy="12" r="2.8" fill="rgba(0, 0, 0, 0.25)" />
      </svg>
    ),
  },
  YouBot: {
    bg: 'linear-gradient(135deg, #10b981 0%, #047857 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M5.5 4.5l4.8 7.3v7.7h3.4v-7.7l4.8-7.3h-3.6L12 9.4 9.1 4.5H5.5z" />
      </svg>
    ),
  },
  MistralBot: {
    bg: 'linear-gradient(135deg, #ff7000 0%, #ea580c 100%)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M3 4h4v4H3V4zm7 0h4v4h-4V4zm7 0h4v4h-4V4zM3 10h18v4H3v-4zm3 6h4v4H6v-4zm8 0h4v4h-4v-4z" />
      </svg>
    ),
  },

  Googlebot: {
    bg: '#ffffff',
    border: '1px solid rgba(0, 0, 0, 0.14)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} aria-hidden="true">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" fill="#FBBC05" />
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" fill="#EA4335" />
      </svg>
    ),
  },
  Bingbot: {
    bg: '#ffffff',
    border: '1px solid rgba(0, 0, 0, 0.14)',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} aria-hidden="true">
        <rect x="2" y="2" width="9.5" height="9.5" fill="#f25022" />
        <rect x="12.5" y="2" width="9.5" height="9.5" fill="#7fba00" />
        <rect x="2" y="12.5" width="9.5" height="9.5" fill="#00a4ef" />
        <rect x="12.5" y="12.5" width="9.5" height="9.5" fill="#ffb900" />
      </svg>
    ),
  },
  DuckDuckGo: {
    bg: '#de5833',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 16.5c-3.5 0-6.2-2.3-6.2-5.5 0-2.2 1.4-4.2 3.6-5.1.4-.2.8-.3 1.2-.4-.2-.5-.3-1-.3-1.5 0-1.7 1.3-3 3-3s3 1.3 3 3c0 .8-.3 1.5-.8 2.1 2.3.9 3.7 3 3.7 5.4 0 3.2-2.7 5-7.2 5zm-.2-10.5c-.8 0-1.5.7-1.5 1.5s.7 1.5 1.5 1.5 1.5-.7 1.5-1.5-.7-1.5-1.5-1.5z" />
      </svg>
    ),
  },
  Baiduspider: {
    bg: '#2932e1',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <ellipse cx="6.5" cy="8" rx="2" ry="3" />
        <ellipse cx="11" cy="5.5" rx="2" ry="3.2" />
        <ellipse cx="16" cy="6" rx="2" ry="3.2" />
        <ellipse cx="19.5" cy="9.5" rx="1.8" ry="2.8" />
        <path d="M12.5 10c-3 0-5.5 2-6 5.5-.3 2 1 4.5 3.5 4.5 1.5 0 2-1 3-1s1.5 1 3 1c2.5 0 3.8-2.5 3.5-4.5-.5-3.5-3-5.5-7-5.5z" />
      </svg>
    ),
  },
  YandexBot: {
    bg: '#fc3f1d',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M6 3h5.5c3.6 0 6.5 2.5 6.5 6 0 2.5-1.4 4.6-3.6 5.5L19 21h-3.8l-4.5-6.2H9.5V21H6V3zm3.5 3v6h2c1.9 0 3.3-1.3 3.3-3s-1.4-3-3.3-3h-2z" />
      </svg>
    ),
  },
  Twitterbot: {
    bg: '#000000',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
      </svg>
    ),
  },
  WhatsApp: {
    bg: '#25d366',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12.04 2c-5.46 0-9.91 4.45-9.91 9.91 0 1.75.46 3.45 1.32 4.95L2.05 22l5.25-1.38c1.45.79 3.08 1.21 4.74 1.21 5.46 0 9.91-4.45 9.91-9.91 0-2.65-1.03-5.14-2.9-7.01A9.816 9.816 0 0012.04 2zm5.78 13.97c-.24.68-1.2 1.25-1.76 1.33-.49.07-1.12.1-3.27-.79-2.75-1.14-4.52-3.92-4.66-4.1-.14-.19-1.12-1.49-1.12-2.84 0-1.35.71-2.01.96-2.28.25-.27.55-.34.73-.34.18 0 .37 0 .53.01.17.01.4-.06.62.48.24.57.81 1.97.88 2.11.07.15.12.32.02.51-.1.2-.15.32-.3.49-.15.18-.32.4-.45.54-.15.15-.31.31-.13.62.18.31.79 1.31 1.7 2.12 1.17 1.04 2.15 1.36 2.46 1.51.31.15.49.13.67-.08.18-.21.79-.92 1-1.24.21-.31.43-.26.71-.16.29.11 1.83.86 2.15 1.02.31.16.52.24.6.37.07.13.07.76-.17 1.44z" />
      </svg>
    ),
  },
  Telegram: {
    bg: '#229ed9',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm5.32 6.84-2.02 9.54c-.15.68-.56.85-1.12.53l-3.08-2.27-1.49 1.43c-.16.16-.3.3-.61.3l.22-3.14 5.72-5.17c.25-.22-.05-.34-.39-.12L8.47 14.47l-3.05-.95c-.66-.21-.68-.66.14-.98l11.93-4.6c.55-.2 1.04.13.83.9z" />
      </svg>
    ),
  },
  LinkedInBot: {
    bg: '#0a66c2',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.46 8.76a1.64 1.64 0 1 0 0-3.28 1.64 1.64 0 0 0 0 3.28m1.39 9.74v-8.37H5.07v8.37h2.78z" />
      </svg>
    ),
  },
  Pinterestbot: {
    bg: '#e60023',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2C6.48 2 2 6.48 2 12c0 4.24 2.65 7.86 6.4 9.3-.09-.79-.17-2 .03-2.86.19-.77 1.2-5.09 1.2-5.09s-.31-.61-.31-1.52c0-1.42.82-2.48 1.85-2.48.87 0 1.29.65 1.29 1.44 0 .88-.56 2.19-.85 3.41-.24 1.02.51 1.85 1.52 1.85 1.82 0 3.22-1.92 3.22-4.69 0-2.45-1.76-4.16-4.28-4.16-2.91 0-4.62 2.18-4.62 4.44 0 .88.34 1.82.76 2.33.08.1.1.19.07.3-.08.33-.26 1.06-.3 1.21-.05.2-.16.24-.37.15-1.38-.64-2.24-2.65-2.24-4.27 0-3.48 2.53-6.67 7.29-6.67 3.83 0 6.8 2.73 6.8 6.37 0 3.8-2.4 6.87-5.73 6.87-1.12 0-2.17-.58-2.53-1.27l-.69 2.63c-.25.96-.93 2.16-1.38 2.9 1.02.31 2.1.48 3.22.48 5.52 0 10-4.48 10-10S17.52 2 12 2z" />
      </svg>
    ),
  },
  Slackbot: {
    bg: '#4a154b',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} aria-hidden="true">
        <path d="M5.04 15.17a2.53 2.53 0 1 1 0-5.05h2.52v2.52a2.53 2.53 0 0 1-2.52 2.53z" fill="#E01E5A" />
        <path d="M6.31 15.17a2.53 2.53 0 0 1 5.05 0v6.31a2.53 2.53 0 1 1-5.05 0v-6.31z" fill="#E01E5A" />
        <path d="M8.83 5.04a2.53 2.53 0 1 1 5.05 0v2.52h-2.52A2.53 2.53 0 0 1 8.83 5.04z" fill="#36C5F0" />
        <path d="M8.83 6.31a2.53 2.53 0 0 1 0 5.05H2.52a2.53 2.53 0 1 1 0-5.05h6.31z" fill="#36C5F0" />
        <path d="M18.96 8.83a2.53 2.53 0 1 1 0 5.05h-2.52V11.36a2.53 2.53 0 0 1 2.52-2.53z" fill="#2EB67D" />
        <path d="M17.69 8.83a2.53 2.53 0 0 1-5.05 0V2.52a2.53 2.53 0 1 1 5.05 0v6.31z" fill="#2EB67D" />
        <path d="M15.17 18.96a2.53 2.53 0 1 1-5.05 0v-2.52h2.52c1.4 0 2.53 1.13 2.53 2.52z" fill="#ECB22E" />
        <path d="M15.17 17.69a2.53 2.53 0 0 1 0-5.05h6.31a2.53 2.53 0 1 1 0 5.05h-6.31z" fill="#ECB22E" />
      </svg>
    ),
  },
  ZoomBot: {
    bg: '#2d8cff',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M4 6.5C4 5.12 5.12 4 6.5 4h8C15.88 4 17 5.12 17 6.5v11c0 1.38-1.12 2.5-2.5 2.5h-8C5.12 20 4 18.88 4 17.5v-11zm14 3.75l4-2.5v8.5l-4-2.5v-3.5z" />
      </svg>
    ),
  },
  Zapier: {
    bg: '#ff4a00',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M10.5 2h3v8.5H22v3h-8.5V22h-3v-8.5H2v-3h8.5V2z" />
      </svg>
    ),
  },
  Stripe: {
    bg: '#635bff',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M13.97 4.06c-1.3-.23-2.61-.35-3.92-.35-2.03 0-3.66.42-4.88 1.26-1.22.84-1.83 2.07-1.83 3.69 0 2.92 2.3 4.6 6.89 5.3 1.14.18 1.96.42 2.45.71.49.29.74.75.74 1.37 0 .5-.22.92-.66 1.25-.44.33-1.12.5-2.04.5-1.05 0-2.2-.21-3.45-.63l-.93 3.52c1.3.49 2.75.73 4.35.73 2.1 0 3.75-.43 4.96-1.29 1.21-.86 1.82-2.11 1.82-3.75 0-2.8-2.31-4.45-6.93-4.95-1.16-.13-1.99-.36-2.5-.7-.51-.34-.76-.84-.76-1.5 0-.5.2-.9.59-1.21.39-.31 1-.46 1.82-.46.99 0 1.95.18 2.87.53l.63-3.72" />
      </svg>
    ),
  },
  PayPal: {
    bg: '#003087',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} aria-hidden="true">
        <path d="M7.08 21.34l.79-5.07h2.65c3.27 0 5.09-1.6 5.09-5.32 0-3.91-2.9-5.83-6.86-5.83H3.8L2 21.34h5.08z" fill="#0079c1" />
        <path d="M9.8 16.27h2.65c3.27 0 5.09-1.6 5.09-5.32 0-3.91-2.9-5.83-6.86-5.83H5.73l-.94 6h2.64c.3 0 .56.2.61.5l.76 4.65z" fill="#00457c" />
      </svg>
    ),
  },
  'Datadog Agent': {
    bg: '#632ca6',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm3.8 14.8c-.5.3-1.2.4-1.8.4-1.6 0-2.8-.9-3.2-2.3l2.8-.7c.2.6.7.9 1.3.9.4 0 .7-.1.9-.3.2-.2.3-.4.3-.7 0-.5-.4-.7-1.1-.9l-1.3-.4c-1.3-.4-2-1.2-2-2.3 0-.8.3-1.5.9-2 .6-.5 1.4-.8 2.4-.8.6 0 1.2.1 1.7.4.5.3.8.7 1 1.2l-2.6.8c-.1-.4-.4-.6-.8-.6-.3 0-.6.1-.8.2-.2.1-.3.3-.3.5 0 .4.4.6 1.1.8l1.3.4c1.4.4 2.1 1.2 2.1 2.3 0 .9-.3 1.6-.9 2.2z" />
      </svg>
    ),
  },
  UptimeRobot: {
    bg: '#141e28',
    border: '1px solid #3bd671',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="#3bd671" aria-hidden="true">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15l-4-4 1.41-1.41L11 14.17l6.59-6.59L19 9l-8 8z" />
      </svg>
    ),
  },
  Pingdom: {
    bg: '#1b1b1b',
    border: '1px solid #ffd100',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="#ffd100" aria-hidden="true">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 14h-2v-2h2v2zm0-4h-2V7h2v5z" />
      </svg>
    ),
  },
  AhrefsBot: {
    bg: '#0064fe',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M4 18h3.2V6H4v12zm6.4 0h3.2V10h-3.2v8zm6.4 0H20V2h-3.2v16z" />
      </svg>
    ),
  },
  SemrushBot: {
    bg: '#ff642d',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm5 11h-4v4h-2v-4H7v-2h4V7h2v4h4v2z" />
      </svg>
    ),
  },
  DotBot: {
    bg: '#007991',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <circle cx="12" cy="12" r="10" fill="none" stroke="white" strokeWidth="2.5" />
        <circle cx="12" cy="12" r="4" fill="white" />
      </svg>
    ),
  },
  MJ12bot: {
    bg: '#0c2340',
    border: '1px solid #1fa3e0',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="#1fa3e0" aria-hidden="true">
        <path d="M12 2l-10 4 2 12 8 4 8-4 2-12-10-4zm0 2.2l7.5 3-1.5 9-6 3-6-3-1.5-9 7.5-3z" />
      </svg>
    ),
  },
  Exabot: {
    bg: '#0096d6',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M4 4h16v2H4V4zm0 6h12v2H4v-2zm0 6h16v2H4v-2z" />
      </svg>
    ),
  },
  SeznamBot: {
    bg: '#cc0000',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15h-2v-2h2v2zm2-4h-4V9h4v4z" />
      </svg>
    ),
  },
  CocCocBot: {
    bg: '#00a859',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2L2 22h20L12 2zm0 4l6 14H6l6-14z" />
      </svg>
    ),
  },
  PetalBot: {
    bg: '#007dff',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2c-3 0-5 4-5 7 0 4 3 8 5 8s5-4 5-8c0-3-2-7-5-7zm0 14c-1 0-2-2-2-4s1-4 2-4 2 2 2 4-1 4-2 4z" />
      </svg>
    ),
  },
  MojeekBot: {
    bg: '#ff7f00',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 15c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5z" />
      </svg>
    ),
  },
  TurnitinBot: {
    bg: '#005072',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
      </svg>
    ),
  },
  'Archive.org_bot': {
    bg: '#2c2c2c',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M12 2L2 7v2h20V7L12 2zm-1 8H9v8h2v-8zm4 0h-2v8h2v-8zm4 0h-2v8h2v-8zM4 18v2h16v-2H4z" />
      </svg>
    ),
  },
  OracleBot: {
    bg: '#f80000',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M16.42 2H7.58C3.06 2 2 4.98 2 12s1.06 10 5.58 10h8.84C20.94 22 22 19.02 22 12s-1.06-10-5.58-10zM12 18c-4.42 0-6-2-6-6s1.58-6 6-6 6 2 6 6-1.58 6-6 6z" />
      </svg>
    ),
  },
  Salesforce: {
    bg: '#00a1e0',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} fill="white" aria-hidden="true">
        <path d="M16.89 9.38c-.37-2.6-2.58-4.62-5.32-4.62-2.18 0-4.05 1.28-4.95 3.12-2.53.07-4.57 2.15-4.57 4.7 0 2.6 2.11 4.71 4.71 4.71h10.42c2.47 0 4.47-2 4.47-4.47 0-2.43-1.94-4.4-4.36-4.44h-.4z" />
      </svg>
    ),
  },
  GrapeshotCrawler: {
    bg: '#5c2d91',
    renderIcon: (s) => (
      <svg viewBox="0 0 24 24" width={s} height={s} aria-hidden="true">
        <circle cx="12" cy="12" r="9" fill="none" stroke="white" strokeWidth="2" />
        <circle cx="12" cy="12" r="5" fill="none" stroke="white" strokeWidth="2" />
        <circle cx="12" cy="12" r="2" fill="white" />
      </svg>
    ),
  },
};

// Normalized alias lookups for resilient matching
const BOT_NAME_ALIASES: Record<string, string> = {
  google: 'Googlebot',
  googlebot: 'Googlebot',
  'google-extended': 'Google-Extended',
  bing: 'Bingbot',
  bingbot: 'Bingbot',
  apple: 'Applebot',
  applebot: 'Applebot',
  duckduckgo: 'DuckDuckGo',
  duckduckbot: 'DuckDuckGo',
  baidu: 'Baiduspider',
  baiduspider: 'Baiduspider',
  yandex: 'YandexBot',
  yandexbot: 'YandexBot',
  twitter: 'Twitterbot',
  twitterbot: 'Twitterbot',
  x: 'Twitterbot',
  whatsapp: 'WhatsApp',
  telegram: 'Telegram',
  linkedin: 'LinkedInBot',
  linkedinbot: 'LinkedInBot',
  pinterest: 'Pinterestbot',
  pinterestbot: 'Pinterestbot',
  amazon: 'Amazonbot',
  amazonbot: 'Amazonbot',
  slack: 'Slackbot',
  slackbot: 'Slackbot',
  zoom: 'ZoomBot',
  zoombot: 'ZoomBot',
  zapier: 'Zapier',
  stripe: 'Stripe',
  paypal: 'PayPal',
  datadog: 'Datadog Agent',
  'datadog agent': 'Datadog Agent',
  uptimerobot: 'UptimeRobot',
  uptime: 'UptimeRobot',
  pingdom: 'Pingdom',
  ahrefs: 'AhrefsBot',
  ahrefsbot: 'AhrefsBot',
  semrush: 'SemrushBot',
  semrushbot: 'SemrushBot',
  dotbot: 'DotBot',
  mj12: 'MJ12bot',
  mj12bot: 'MJ12bot',
  exabot: 'Exabot',
  seznam: 'SeznamBot',
  seznambot: 'SeznamBot',
  coccoc: 'CocCocBot',
  coccocbot: 'CocCocBot',
  petal: 'PetalBot',
  petalbot: 'PetalBot',
  mojeek: 'MojeekBot',
  mojeekbot: 'MojeekBot',
  turnitin: 'TurnitinBot',
  turnitinbot: 'TurnitinBot',
  'archive.org_bot': 'Archive.org_bot',
  'archive.org': 'Archive.org_bot',
  archive: 'Archive.org_bot',
  oracle: 'OracleBot',
  oraclebot: 'OracleBot',
  salesforce: 'Salesforce',
  grapeshot: 'GrapeshotCrawler',
  grapeshotcrawler: 'GrapeshotCrawler',
  facebook: 'FacebookBot',
  facebookbot: 'FacebookBot',
  facebookexternalhit: 'FacebookBot',
  meta: 'FacebookBot',

  gptbot: 'GPTBot',
  'chatgpt-user': 'ChatGPT-User',
  'claude-web': 'Claude-Web',
  'anthropic-ai': 'Anthropic-AI',
  perplexitybot: 'PerplexityBot',
  perplexity: 'PerplexityBot',
  ccbot: 'CCBot',
  bytespider: 'Bytespider',
  bytedance: 'Bytespider',
  omgilibot: 'Omgilibot',
  diffbot: 'Diffbot',
  cohere: 'Cohere',
  youbot: 'YouBot',
  mistralbot: 'MistralBot',
};

const CATEGORY_DEFINITIONS: Record<string, BrandDefinition> = {
  OpenAI: BRAND_DEFINITIONS.GPTBot,
  Anthropic: BRAND_DEFINITIONS['Claude-Web'],
  Google: BRAND_DEFINITIONS['Google-Extended'],
  Microsoft: BRAND_DEFINITIONS.Bingbot,
  Apple: BRAND_DEFINITIONS.Applebot,
  Perplexity: BRAND_DEFINITIONS.PerplexityBot,
  'Common Crawl': BRAND_DEFINITIONS.CCBot,
  ByteDance: BRAND_DEFINITIONS.Bytespider,
  Meta: BRAND_DEFINITIONS.FacebookBot,
  Amazon: BRAND_DEFINITIONS.Amazonbot,
  'Webz.io': BRAND_DEFINITIONS.Omgilibot,
  Diffbot: BRAND_DEFINITIONS.Diffbot,
  Cohere: BRAND_DEFINITIONS.Cohere,
  'You.com': BRAND_DEFINITIONS.YouBot,
  Slack: BRAND_DEFINITIONS.Slackbot,
  Zoom: BRAND_DEFINITIONS.ZoomBot,
  Zapier: BRAND_DEFINITIONS.Zapier,
  Stripe: BRAND_DEFINITIONS.Stripe,
  PayPal: BRAND_DEFINITIONS.PayPal,
  Datadog: BRAND_DEFINITIONS['Datadog Agent'],
  UptimeRobot: BRAND_DEFINITIONS.UptimeRobot,
  SolarWinds: BRAND_DEFINITIONS.Pingdom,
  Ahrefs: BRAND_DEFINITIONS.AhrefsBot,
  Semrush: BRAND_DEFINITIONS.SemrushBot,
  Moz: BRAND_DEFINITIONS.DotBot,
  Majestic: BRAND_DEFINITIONS.MJ12bot,
  Exalead: BRAND_DEFINITIONS.Exabot,
  Seznam: BRAND_DEFINITIONS.SeznamBot,
  'Cốc Cốc': BRAND_DEFINITIONS.CocCocBot,
  Huawei: BRAND_DEFINITIONS.PetalBot,
  Mojeek: BRAND_DEFINITIONS.MojeekBot,
  Turnitin: BRAND_DEFINITIONS.TurnitinBot,
  'Internet Archive': BRAND_DEFINITIONS['Archive.org_bot'],
  Oracle: BRAND_DEFINITIONS.OracleBot,
  Salesforce: BRAND_DEFINITIONS.Salesforce,
};

export const BotBrandLogo: React.FC<BotBrandLogoProps> = ({
  botName,
  category,
  size = 38,
  className,
  style,
}) => {
  const normalizedKey = botName.trim().toLowerCase();
  const aliasMatch = BOT_NAME_ALIASES[normalizedKey];
  const resolvedName = aliasMatch || botName;

  const brand =
    BRAND_DEFINITIONS[resolvedName] ||
    BRAND_DEFINITIONS[botName] ||
    (category && CATEGORY_DEFINITIONS[category]) ||
    null;

  const iconSize = Math.round(size * 0.54);

  if (brand) {
    return (
      <div
        className={className}
        style={{
          width: `${size}px`,
          height: `${size}px`,
          borderRadius: 0,
          background: brand.bg,
          border: brand.border || '1px solid rgba(255, 255, 255, 0.16)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          boxSizing: 'border-box',
          ...style,
        }}
        title={`${botName}${category ? ` (${category})` : ''}`}
      >
        {brand.renderIcon(iconSize)}
      </div>
    );
  }

  const initials = botName
    .split(/[-_ ]/)
    .map((w) => w.charAt(0))
    .join('')
    .substring(0, 2)
    .toUpperCase();

  return (
    <div
      className={className}
      style={{
        width: `${size}px`,
        height: `${size}px`,
        borderRadius: 0,
        background: 'linear-gradient(135deg, var(--cds-interactive, #ff832b) 0%, #eb6200 100%)',
        color: '#ffffff',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontWeight: 700,
        fontSize: `${Math.round(size * 0.36)}px`,
        letterSpacing: '0.5px',
        flexShrink: 0,
        border: '1px solid rgba(255, 255, 255, 0.16)',
        boxSizing: 'border-box',
        ...style,
      }}
      title={`${botName}${category ? ` (${category})` : ''}`}
    >
      {initials}
    </div>
  );
};

export default BotBrandLogo;
