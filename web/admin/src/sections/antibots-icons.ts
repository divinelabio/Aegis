export function getAntibotBotIconChar(name: string): string {
    const n = name.toLowerCase();

    const svgs = {
        google: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12.48 10.92v3.28h7.84c-.24 1.84-.853 3.187-1.787 4.133-1.147 1.147-2.933 2.4-6.053 2.4-4.827 0-8.6-3.893-8.6-8.72s3.773-8.72 8.6-8.72c2.6 0 4.507 1.027 5.907 2.347l2.307-2.307C18.747 1.44 16.133 0 12.48 0 5.867 0 .533 5.333.533 12S5.867 24 12.48 24c3.44 0 6.013-1.147 8.027-3.24 2.053-2.053 2.627-5.027 2.627-7.467 0-.76-.053-1.467-.173-2.373H12.48z"/></svg>',
        bing: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M3.5 2v20l14.3-8.3-4.5-2.6 4.3-2.5-9.3-5.2z"/></svg>',
        duck: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z"/></svg>',
        yandex: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M11 20H6v-2h2.5c1.1 0 2-.9 2-2V8.5L5.6 2h2.5l3.2 5.2L14.5 2h2.4l-5.7 8.5L16 20h-2.5l-2.5-4h-2V20z"/></svg>',
        apple: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.8-1.31.02-2.3-1.23-3.14-2.47-1.7-2.45-3-6.24-1.24-9.28 1.76-3.04 5.32-3.14 7.23-1.25.9-1.09 2.1-1.29 2.85-1.29 2.14 0 3.73 1.25 4.6 2.5-3.66 1.95-3.05 6.6 1.31 8.31zM13 3.5c.53-1.39 2.22-2.5 3.5-2.5.2 1.48-1.28 2.92-2.38 3.6-1.55.97-3.15.22-3.15.22-.09-1.27.03-1.32 2.03-1.32z"/></svg>',
        facebook: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>',
        twitter: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.84 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"/></svg>',
        whatsapp: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12.04 2c-5.46 0-9.91 4.45-9.91 9.91 0 1.75.46 3.45 1.32 4.95L2.05 22l5.25-1.38c1.45.79 3.08 1.21 4.74 1.21 5.46 0 9.91-4.45 9.91-9.91 0-2.65-1.03-5.14-2.9-7.01A9.816 9.816 0 0012.04 2z"/></svg>',
        telegram: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M9.78 18.65l.28-4.28 7.27-6.57-6.85 4.63-3.08 1.54 2.38 4.68zm-2.06-4.9l-5.38-1.74 18.06-7.3-6.2 16.32-4.96-3.84z"/></svg>',
        zapier: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 12h16M12 4v16" stroke="currentColor" stroke-width="4"/></svg>',
        stripe: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13.97 4.06c-1.3-.23-2.61-.35-3.92-.35-2.03 0-3.66.42-4.88 1.26-1.22.84-1.83 2.07-1.83 3.69 0 2.92 2.3 4.6 6.89 5.3 1.14.18 1.96.42 2.45.71.49.29.74.75.74 1.37 0 .5-.22.92-.66 1.25-.44.33-1.12.5-2.04.5-1.05 0-2.2-.21-3.45-.63l-.93 3.52c1.3.49 2.75.73 4.35.73 2.1 0 3.75-.43 4.96-1.29 1.21-.86 1.82-2.11 1.82-3.75 0-2.8-2.31-4.45-6.93-4.95-1.16-.13-1.99-.36-2.5-.7-.51-.34-.76-.84-.76-1.5 0-.5.2-.9.59-1.21.39-.31 1-.46 1.82-.46.99 0 1.95.18 2.87.53l.63-3.72"/></svg>',
        paypal: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M7.076 21.337l.794-5.07h2.646c3.27 0 5.093-1.603 5.093-5.32 0-3.905-2.903-5.834-6.864-5.834h-4.95L2 21.337h5.076z"/></svg>',
        slack: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 6.313 18.954v-3.789zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.52v2.52h-2.521zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.52v3.79H6.313A2.528 2.528 0 0 1 8.834 6.313zm10.124 3.79a2.528 2.528 0 0 1 2.52 2.52 2.528 2.528 0 0 1 2.522-2.52H24v-2.52a2.528 2.528 0 0 1-2.522 2.52zM17.688 8.833a2.528 2.528 0 0 1-2.522 2.521h-3.79V5.042a2.528 2.528 0 0 1 2.521 2.521v1.27h3.791zM15.166 18.958a2.528 2.528 0 0 1 2.522 2.521 2.528 2.528 0 0 1-2.522 2.521 2.527 2.527 0 0 1-2.52-2.521v-2.52h2.52zM15.166 17.688a2.527 2.527 0 0 1-2.522-2.521v-3.791h5.043a2.528 2.528 0 0 1-2.521 2.521v3.79z"/></svg>',
        pinterest: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.372 0 0 5.372 0 12c0 5.084 3.163 9.426 7.627 11.174-.105-.949-.2-2.405.042-3.441.218-.937 1.407-5.965 1.407-5.965s-.359-.719-.359-1.782c0-1.668.967-2.914 2.171-2.914 1.023 0 1.518.769 1.518 1.69 0 1.029-.655 2.568-.994 3.995-.283 1.194.599 2.169 1.777 2.169 2.133 0 3.772-2.249 3.772-5.495 0-2.873-2.064-4.882-5.012-4.882-3.65 0-5.789 2.738-5.789 5.57 0 1.104.425 2.288.956 2.932.105.128.12.24.088.37l-.36 1.48c-.056.23-.214.28-.492.148-1.836-.855-2.983-3.543-2.983-5.699 0-4.639 3.37-8.89 9.715-8.89 5.1 0 9.064 3.636 9.064 8.498 0 5.071-3.197 9.157-7.633 9.157-1.492 0-2.894-.775-3.374-1.691l-.916 3.489c-.334 1.286-1.239 2.896-1.848 3.882C6.012 23.86 8.92 24 12 24c6.627 0 12-5.373 12-12 0-6.628-5.373-12-12-12z"/></svg>',
        linkedin: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>',
        amazon: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13.88 15.65c-3.17-.11-5.34 1.11-5.34 3.23 0 1.94 1.71 3.03 3.6 3.03 2 0 3.34-1.08 3.34-1.08l-.11-5.18zm6.54-5.37c-.17-.03-.43-.03-.63 0-.8.14-1.66 1-1.66 1l-.09-3.03c0-3.08-1.57-4.65-4.57-4.65-3.37 0-4.94 1.77-5.34 3.74l1.6 1.08c.2-.97.74-2.8 3.68-1.91.83.26 1.34 1.28 1.31 2.51l-.09 1.83c-5.91.31-9.42 2.68-9.42 6.62 0 3.05 2 5.08 5.4 5.08 3.08 0 4.65-1.77 4.65-1.77l.23 1.6h3.48v-8.8c.03-2.09-.77-3.14-1.57-3.3zm-6.08 8.4h-.14c-1.28 0-1.71-.69-1.71-1.77 0-1.11 1-1.6 2.37-1.54l1.37.06-.06 3.63-1.83-.38z"/></svg>',
        oracle: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M16.42 2H7.58C3.06 2 2 4.98 2 12s1.06 10 5.58 10h8.84C20.94 22 22 19.02 22 12s-1.06-10-5.58-10zM12 18c-4.42 0-6-2-6-6s1.58-6 6-6 6 2 6 6-1.58 6-6 6z"/></svg>',
        salesforce: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M16.89 9.38c-.37-2.6-2.58-4.62-5.32-4.62-2.18 0-4.05 1.28-4.95 3.12-2.53.07-4.57 2.15-4.57 4.7 0 2.6 2.11 4.71 4.71 4.71h10.42c2.47 0 4.47-2 4.47-4.47 0-2.43-1.94-4.4-4.36-4.44h-.4z"/></svg>',
        mj12: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l-10 4 2 12 8 4 8-4 2-12-10-4zm0 2.2l7.5 3-1.5 9-6 3-6-3-1.5-9 7.5-3z"/></svg>',
        dotbot: '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4"/></svg>',
        ahrefs: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 4h16v16H4V4zm4 4v8h2V8H8zm4 0v8h2V8h-2zm4 0v8h2V8h-2z"/></svg>',
        semrush: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>',
        archive: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L2 7v2h20V7L12 2zm-1 8H9v8h2v-8zm4 0h-2v8h2v-8zm4 0h-2v8h2v-8zM4 18v2h16v-2H4z"/></svg>',
        exabot: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M4 4h16v2H4V4zm0 6h12v2H4v-2zm0 6h16v2H4v-2z"/></svg>',
        seznam: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15h-2v-2h2v2zm2-4h-4V9h4v4z"/></svg>',
        coccoc: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L2 22h20L12 2zm0 4l6 14H6l6-14z"/></svg>',
        petal: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2c-3 0-5 4-5 7 0 4 3 8 5 8s5-4 5-8c0-3-2-7-5-7zm0 14c-1 0-2-2-2-4s1-4 2-4 2 2 2 4-1 4-2 4z"/></svg>',
        turnitin: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>',
        mojeek: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 15c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5z"/></svg>',
        grapeshot: '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4"/></svg>',
        datadog: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M20 4H4v16h16V4zm-2 14H6V6h12v12z"/></svg>',
        zoom: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14 8.7V17c0 1.1-.9 2-2 2H3c-1.1 0-2-.9-2-2V7c0-1.1.9-2 2-2h9c1.1 0 2 .9 2 2v2.7l5-4v10.6l-5-4z"/></svg>',
        uptime: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 14h-2v-2h2v2zm0-4h-2V7h2v5z"/></svg>',
        pingdom: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M16 6l2.29 2.29-4.88 4.88-4-4L2 16.59 3.41 18l6-6 4 4 6.3-6.29L22 12V6z"/></svg>'
    };

    if (n.includes('google')) return svgs.google;
    if (n.includes('bing')) return svgs.bing;
    if (n.includes('duck')) return svgs.duck;
    if (n.includes('yandex')) return svgs.yandex;
    if (n.includes('apple')) return svgs.apple;
    if (n.includes('facebook')) return svgs.facebook;
    if (n.includes('twitter')) return svgs.twitter;
    if (n.includes('whats')) return svgs.whatsapp;
    if (n.includes('telegram')) return svgs.telegram;
    if (n.includes('slack')) return svgs.slack;
    if (n.includes('linkedin')) return svgs.linkedin;
    if (n.includes('pinterest')) return svgs.pinterest;
    if (n.includes('amazon')) return svgs.amazon;
    if (n.includes('oracle')) return svgs.oracle;
    if (n.includes('salesforce')) return svgs.salesforce;
    if (n.includes('archive')) return svgs.archive;
    if (n.includes('mj12')) return svgs.mj12;
    if (n.includes('dotbot')) return svgs.dotbot;
    if (n.includes('ahrefs')) return svgs.ahrefs;
    if (n.includes('semrush')) return svgs.semrush;
    if (n.includes('exabot')) return svgs.exabot;
    if (n.includes('seznam')) return svgs.seznam;
    if (n.includes('coccoc')) return svgs.coccoc;
    if (n.includes('petal')) return svgs.petal;
    if (n.includes('turnitin')) return svgs.turnitin;
    if (n.includes('mojeek')) return svgs.mojeek;
    if (n.includes('grapeshot')) return svgs.grapeshot;
    if (n.includes('zapier')) return svgs.zapier;
    if (n.includes('stripe')) return svgs.stripe;
    if (n.includes('paypal')) return svgs.paypal;
    if (n.includes('zoom')) return svgs.zoom;
    if (n.includes('uptime')) return svgs.uptime;
    if (n.includes('pingdom')) return svgs.pingdom;
    if (n.includes('datadog')) return svgs.datadog;

    return name.substring(0, 2).toUpperCase();
}
