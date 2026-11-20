// Stroke icons from the selected console mockup. SVG nodes use the SVG namespace.
const paths = {
  overview: ['M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z'],
  map: ['M8.5 7.5l7 .8M8 9l1.5 6.5M16 10.5l-4.5 5.5'],
  findings: ['M12 3l9 16H3z', 'M12 10v4M12 17v.5'],
  devices: ['M8 20h8'],
  actions: ['M5 12l4 4L19 6'],
  peers: ['M9 7V3M15 7V3M7 7h10v5a5 5 0 0 1-10 0zM12 17v4'],
  integrations: ['M8 3v5M16 3v5M5 8h14v3a7 7 0 0 1-14 0zM12 18v3'],
  events: ['M4 6h16M4 12h16M4 18h10'],
  chevron: ['M15 5l-7 7 7 7'],
};
export function icon(name) {
  const ns = 'http://www.w3.org/2000/svg';
  const node = (tag, attrs) => {
    const n = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attrs)) n.setAttribute(key, value);
    return n;
  };
  const svg = node('svg', { viewBox: '0 0 24 24', width: '20', height: '20', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.8', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', class: 'nav-icon' });
  for (const d of paths[name] || paths.events) svg.append(node('path', { d }));
  if (name === 'map') for (const [cx, cy] of [[6, 6], [18, 8], [10, 18]]) svg.append(node('circle', { cx, cy, r: 3 }));
  if (name === 'devices') svg.append(node('rect', { x: 3, y: 4, width: 18, height: 12, rx: 2 }));
  return svg;
}
