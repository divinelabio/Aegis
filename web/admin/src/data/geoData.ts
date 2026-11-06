/* * * Traffic Control - Geographic Access Control Data * Country (ISO Alpha-2), Global Regions, and regional memberships. */

export const REGIONS_MAP: Record<string, string> = {
  EU: 'European Union',
  EEA: 'European Economic Area',
  SCHENGEN: 'Schengen Area',
  BENELUX: 'Benelux',
  DACH: 'Germany, Austria & Switzerland',
  NORDICS: 'Nordic Countries',
  USMCA: 'United States, Mexico & Canada',
  FIVE_EYES: 'Five Eyes',
  ASEAN: 'ASEAN',
  GCC: 'Gulf Cooperation Council',
  G7: 'Group of Seven',
  APAC: 'Asia-Pacific',
  LATAM: 'Latin America',
  MENA: 'Middle East & North Africa',
  AFRICA: 'Africa',
  CIS: 'CIS (Former Soviet)',
};

export const REGION_ICONS: Record<string, string> = {
  EU: 'EU',
  EEA: 'EEA',
  SCHENGEN: 'SCH',
  BENELUX: 'BNL',
  DACH: 'DACH',
  NORDICS: 'NOR',
  USMCA: 'USMCA',
  FIVE_EYES: '5EYE',
  ASEAN: 'ASEAN',
  GCC: 'GCC',
  G7: 'G7',
  APAC: 'APAC',
  LATAM: 'LATAM',
  MENA: 'MENA',
  AFRICA: 'AFR',
  CIS: 'CIS',
};

export const REGION_MEMBERS: Record<string, string[]> = {
  EU: [
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU',
    'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'
  ],
  EEA: [
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU',
    'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
    'IS', 'LI', 'NO'
  ],
  SCHENGEN: [
    'AT', 'BE', 'BG', 'HR', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IS',
    'IT', 'LV', 'LI', 'LT', 'LU', 'MT', 'NL', 'NO', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE', 'CH'
  ],
  BENELUX: ['BE', 'NL', 'LU'],
  DACH: ['DE', 'AT', 'CH'],
  NORDICS: ['DK', 'FI', 'IS', 'NO', 'SE'],
  USMCA: ['US', 'CA', 'MX'],
  FIVE_EYES: ['AU', 'CA', 'NZ', 'GB', 'US'],
  ASEAN: ['BN', 'KH', 'ID', 'LA', 'MY', 'MM', 'PH', 'SG', 'TH', 'VN'],
  GCC: ['BH', 'KW', 'OM', 'QA', 'SA', 'AE'],
  G7: ['CA', 'FR', 'DE', 'IT', 'JP', 'GB', 'US'],
  APAC: [
    'AU', 'BD', 'BN', 'KH', 'CN', 'HK', 'IN', 'ID', 'JP', 'KP', 'KR', 'LA', 'MY',
    'MV', 'MN', 'MM', 'NP', 'NZ', 'PK', 'PH', 'SG', 'LK', 'TW', 'TH', 'TL', 'VN'
  ],
  LATAM: [
    'AR', 'BO', 'BR', 'CL', 'CO', 'CR', 'CU', 'DO', 'EC', 'SV', 'GT', 'HN', 'MX',
    'NI', 'PA', 'PY', 'PE', 'UY', 'VE'
  ],
  MENA: [
    'DZ', 'BH', 'EG', 'IQ', 'IL', 'JO', 'KW', 'LB', 'LY', 'MA', 'OM', 'PS', 'QA',
    'SA', 'SY', 'TN', 'AE', 'YE'
  ],
  AFRICA: [
    'AO', 'BJ', 'BW', 'BF', 'BI', 'CM', 'CV', 'CF', 'TD', 'KM', 'CG', 'CD', 'CI',
    'DJ', 'GQ', 'ER', 'ET', 'GA', 'GM', 'GH', 'GN', 'GW', 'KE', 'LS', 'LR', 'MG',
    'MW', 'ML', 'MR', 'MU', 'MZ', 'NA', 'NE', 'NG', 'RW', 'ST', 'SN', 'SC', 'SL',
    'SO', 'ZA', 'SS', 'SD', 'SZ', 'TZ', 'TG', 'UG', 'ZM', 'ZW'
  ],
  CIS: ['RU', 'BY', 'KZ', 'KG', 'TJ', 'TM', 'UZ', 'AM', 'AZ', 'GE', 'MD', 'UA'],
};

export const COUNTRIES_MAP: Record<string, string> = {
  AF: 'Afghanistan', AL: 'Albania', DZ: 'Algeria', AS: 'American Samoa', AD: 'Andorra',
  AO: 'Angola', AI: 'Anguilla', AQ: 'Antarctica', AG: 'Antigua and Barbuda', AR: 'Argentina',
  AM: 'Armenia', AW: 'Aruba', AU: 'Australia', AT: 'Austria', AZ: 'Azerbaijan',
  BS: 'Bahamas', BH: 'Bahrain', BD: 'Bangladesh', BB: 'Barbados', BY: 'Belarus',
  BE: 'Belgium', BZ: 'Belize', BJ: 'Benin', BM: 'Bermuda', BT: 'Bhutan',
  BO: 'Bolivia', BA: 'Bosnia and Herzegovina', BW: 'Botswana', BV: 'Bouvet Island', BR: 'Brazil',
  IO: 'British Indian Ocean Territory', BN: 'Brunei Darussalam', BG: 'Bulgaria', BF: 'Burkina Faso', BI: 'Burundi',
  KH: 'Cambodia', CM: 'Cameroon', CA: 'Canada', CV: 'Cape Verde', KY: 'Cayman Islands',
  CF: 'Central African Republic', TD: 'Chad', CL: 'Chile', CN: 'China', CX: 'Christmas Island',
  CC: 'Cocos (Keeling) Islands', CO: 'Colombia', KM: 'Comoros', CG: 'Congo', CD: 'Congo, Democratic Republic',
  CK: 'Cook Islands', CR: 'Costa Rica', CI: "Cote D'Ivoire", HR: 'Croatia', CU: 'Cuba',
  CY: 'Cyprus', CZ: 'Czech Republic', DK: 'Denmark', DJ: 'Djibouti', DM: 'Dominica',
  DO: 'Dominican Republic', EC: 'Ecuador', EG: 'Egypt', SV: 'El Salvador', GQ: 'Equatorial Guinea',
  ER: 'Eritrea', EE: 'Estonia', ET: 'Ethiopia', FK: 'Falkland Islands', FO: 'Faroe Islands',
  FJ: 'Fiji', FI: 'Finland', FR: 'France', GF: 'French Guiana', PF: 'French Polynesia',
  TF: 'French Southern Territories', GA: 'Gabon', GM: 'Gambia', GE: 'Georgia', DE: 'Germany',
  GH: 'Ghana', GI: 'Gibraltar', GR: 'Greece', GL: 'Greenland', GD: 'Grenada',
  GP: 'Guadeloupe', GU: 'Guam', GT: 'Guatemala', GN: 'Guinea', GW: 'Guinea-Bissau',
  GY: 'Guyana', HT: 'Haiti', HM: 'Heard Island and Mcdonald Islands', VA: 'Holy See (Vatican City State)', HN: 'Honduras',
  HK: 'Hong Kong', HU: 'Hungary', IS: 'Iceland', IN: 'India', ID: 'Indonesia',
  IR: 'Iran', IQ: 'Iraq', IE: 'Ireland', IL: 'Israel', IT: 'Italy',
  JM: 'Jamaica', JP: 'Japan', JO: 'Jordan', KZ: 'Kazakhstan', KE: 'Kenya',
  KI: 'Kiribati', KP: 'Korea, North', KR: 'Korea, South', KW: 'Kuwait', KG: 'Kyrgyzstan',
  LA: "Lao People's Democratic Republic", LV: 'Latvia', LB: 'Lebanon', LS: 'Lesotho', LR: 'Liberia',
  LY: 'Libyan Arab Jamahiriya', LI: 'Liechtenstein', LT: 'Lithuania', LU: 'Luxembourg', MO: 'Macao',
  MK: 'Macedonia', MG: 'Madagascar', MW: 'Malawi', MY: 'Malaysia', MV: 'Maldives',
  ML: 'Mali', MT: 'Malta', MH: 'Marshall Islands', MQ: 'Martinique', MR: 'Mauritania',
  MU: 'Mauritius', YT: 'Mayotte', MX: 'Mexico', FM: 'Micronesia', MD: 'Moldova',
  MC: 'Monaco', MN: 'Mongolia', MS: 'Montserrat', MA: 'Morocco', MZ: 'Mozambique',
  MM: 'Myanmar', NA: 'Namibia', NR: 'Nauru', NP: 'Nepal', NL: 'Netherlands',
  AN: 'Netherlands Antilles', NC: 'New Caledonia', NZ: 'New Zealand', NI: 'Nicaragua', NE: 'Niger',
  NG: 'Nigeria', NU: 'Niue', NF: 'Norfolk Island', MP: 'Northern Mariana Islands', NO: 'Norway',
  OM: 'Oman', PK: 'Pakistan', PW: 'Palau', PS: 'Palestinian Territory', PA: 'Panama',
  PG: 'Papua New Guinea', PY: 'Paraguay', PE: 'Peru', PH: 'Philippines', PN: 'Pitcairn',
  PL: 'Poland', PT: 'Portugal', PR: 'Puerto Rico', QA: 'Qatar', RE: 'Reunion',
  RO: 'Romania', RU: 'Russia', RW: 'Rwanda', SH: 'Saint Helena', KN: 'Saint Kitts and Nevis',
  LC: 'Saint Lucia', PM: 'Saint Pierre and Miquelon', VC: 'Saint Vincent and the Grenadines', WS: 'Samoa', SM: 'San Marino',
  ST: 'Sao Tome and Principe', SA: 'Saudi Arabia', SN: 'Senegal', CS: 'Serbia and Montenegro', SC: 'Seychelles',
  SL: 'Sierra Leone', SG: 'Singapore', SK: 'Slovakia', SI: 'Slovenia', SB: 'Solomon Islands',
  SO: 'Somalia', ZA: 'South Africa', GS: 'South Georgia and the South Sandwich Islands', ES: 'Spain', LK: 'Sri Lanka',
  SD: 'Sudan', SR: 'Suriname', SJ: 'Svalbard and Jan Mayen', SZ: 'Swaziland', SE: 'Sweden',
  CH: 'Switzerland', SY: 'Syria', TW: 'Taiwan', TJ: 'Tajikistan', TZ: 'Tanzania',
  TH: 'Thailand', TL: 'Timor-Leste', TG: 'Togo', TK: 'Tokelau', TO: 'Tonga',
  TT: 'Trinidad and Tobago', TN: 'Tunisia', TR: 'Turkey', TM: 'Turkmenistan', TC: 'Turks and Caicos Islands',
  TV: 'Tuvalu', UG: 'Uganda', UA: 'Ukraine', AE: 'United Arab Emirates', GB: 'United Kingdom',
  US: 'United States', UM: 'United States Minor Outlying Islands', UY: 'Uruguay', UZ: 'Uzbekistan', VU: 'Vanuatu',
  VE: 'Venezuela', VN: 'Vietnam', VG: 'Virgin Islands, British', VI: 'Virgin Islands, U.S.',
  WF: 'Wallis and Futuna', EH: 'Western Sahara', YE: 'Yemen', ZM: 'Zambia', ZW: 'Zimbabwe',
};

export const COUNTRY_NAME_TO_CODE: Record<string, string> = Object.entries(COUNTRIES_MAP).reduce(
  (acc, [code, name]) => {
    acc[name.toLowerCase()] = code;
    return acc;
  },
  {} as Record<string, string>
);

export function normalizeToCountryCode(input?: string): string | null {
  if (!input) return null;
  const trimmed = input.trim();
  const upper = trimmed.toUpperCase();
  if (/^[A-Z]{2}$/.test(upper)) {
    if (upper === 'XX' || upper === 'T1' || upper === 'ZZ') return null;
    return upper;
  }
  const codeFromName = COUNTRY_NAME_TO_CODE[trimmed.toLowerCase()];
  if (codeFromName) return codeFromName;
  return null;
}

export function trafficCountryFlag(code?: string): string {
  const normalized = normalizeToCountryCode(code);
  if (!normalized) return '';
  const codePoints = [...normalized].map((c) => 0x1F1E6 - 65 + c.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

export const countryCodeToFlag = trafficCountryFlag;

export function getGeoHighlightedCountries(
  selectedCountries: string[],
  selectedRegions: string[]
): string[] {
  const highlighted = new Set<string>(selectedCountries.map((c) => c.toUpperCase()));
  for (const region of selectedRegions) {
    const cleanRegion = region.replace(/^@/, '').toUpperCase();
    const members = REGION_MEMBERS[cleanRegion] || [];
    for (const code of members) {
      highlighted.add(code.toUpperCase());
    }
  }
  return Array.from(highlighted);
}

/**
 * Comprehensive ISO Alpha-2 country name mapping used across Geo-blocking and Events
 * Uses COUNTRIES_MAP (the complete country database used in geoblocklist).
 */
export const countryNames: Record<string, string> = COUNTRIES_MAP;

export function getCountryName(code?: string): string {
  if (!code) return '';
  const upper = code.trim().toUpperCase();
  return COUNTRIES_MAP[upper] || upper;
}
