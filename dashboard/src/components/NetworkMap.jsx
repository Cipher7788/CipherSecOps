import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';

/* ── Mock topology ─────────────────────────────────────── */
const NODES = [
  { id: 'internet',   label: 'Internet',    group: 'external', threat: 'critical', icon: '🌐' },
  { id: 'fw01',       label: 'Firewall',    group: 'perimeter',threat: 'none',     icon: '🔥' },
  { id: 'WIN-DC01',   label: 'WIN-DC01',    group: 'server',   threat: 'critical', icon: '🪟' },
  { id: 'WIN-WEB02',  label: 'WIN-WEB02',   group: 'server',   threat: 'high',     icon: '🪟' },
  { id: 'WIN-APP03',  label: 'WIN-APP03',   group: 'server',   threat: 'high',     icon: '🪟' },
  { id: 'WIN-FS01',   label: 'WIN-FS01',    group: 'server',   threat: 'critical', icon: '🪟' },
  { id: 'LNX-NGINX',  label: 'LNX-NGINX',   group: 'server',   threat: 'medium',   icon: '🐧' },
  { id: 'LNX-API01',  label: 'LNX-API01',   group: 'server',   threat: 'medium',   icon: '🐧' },
  { id: 'LNX-DNS01',  label: 'LNX-DNS01',   group: 'server',   threat: 'high',     icon: '🐧' },
  { id: 'AWS-PROD',   label: 'AWS-PROD',    group: 'cloud',    threat: 'medium',   icon: '☁️' },
];

const LINKS = [
  { source: 'internet',  target: 'fw01' },
  { source: 'fw01',      target: 'WIN-WEB02' },
  { source: 'fw01',      target: 'LNX-NGINX' },
  { source: 'WIN-WEB02', target: 'WIN-APP03' },
  { source: 'WIN-WEB02', target: 'WIN-DC01' },
  { source: 'WIN-APP03', target: 'WIN-DC01' },
  { source: 'WIN-DC01',  target: 'WIN-FS01' },
  { source: 'LNX-NGINX', target: 'LNX-API01' },
  { source: 'LNX-API01', target: 'LNX-DNS01' },
  { source: 'LNX-API01', target: 'AWS-PROD' },
  { source: 'WIN-DC01',  target: 'AWS-PROD' },
];

const THREAT_COLOR = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#10b981',
  none:     '#3b82f6',
};

export default function NetworkMap() {
  const svgRef = useRef(null);

  useEffect(() => {
    const container = svgRef.current.parentElement;
    const W = container.clientWidth  || 800;
    const H = container.clientHeight || 520;

    const svg = d3.select(svgRef.current)
      .attr('width', W)
      .attr('height', H);

    svg.selectAll('*').remove();

    const defs = svg.append('defs');
    // Arrow markers for directional links
    Object.entries(THREAT_COLOR).forEach(([key, color]) => {
      defs.append('marker')
        .attr('id', `arrow-${key}`)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 22)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', color);
    });

    const g = svg.append('g');

    // Zoom + pan
    svg.call(
      d3.zoom()
        .scaleExtent([0.4, 3])
        .on('zoom', (event) => g.attr('transform', event.transform))
    );

    const nodes = NODES.map((n) => ({ ...n }));
    const links = LINKS.map((l) => ({ ...l }));

    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d) => d.id).distance(120))
      .force('charge', d3.forceManyBody().strength(-400))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide(40));

    // Links
    const link = g.append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', (d) => {
        const src = nodes.find((n) => n.id === (d.source.id ?? d.source));
        return THREAT_COLOR[src?.threat ?? 'none'];
      })
      .attr('stroke-opacity', 0.5)
      .attr('stroke-width', 1.5)
      .attr('marker-end', (d) => {
        const src = nodes.find((n) => n.id === (d.source.id ?? d.source));
        return `url(#arrow-${src?.threat ?? 'none'})`;
      });

    // Node groups
    const node = g.append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .call(
        d3.drag()
          .on('start', (event, d) => { if (!event.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
          .on('drag',  (event, d) => { d.fx = event.x; d.fy = event.y; })
          .on('end',   (event, d) => { if (!event.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    // Glow circle for critical nodes
    node.filter((d) => d.threat === 'critical')
      .append('circle')
      .attr('r', 22)
      .attr('fill', 'none')
      .attr('stroke', '#ef4444')
      .attr('stroke-width', 2)
      .attr('stroke-opacity', 0.4)
      .attr('class', 'animate-ping');

    // Node circle
    node.append('circle')
      .attr('r', 18)
      .attr('fill', (d) => `${THREAT_COLOR[d.threat]}22`)
      .attr('stroke', (d) => THREAT_COLOR[d.threat])
      .attr('stroke-width', 2);

    // Node icon (emoji via foreignObject for browser rendering)
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('font-size', 14)
      .text((d) => d.icon);

    // Label
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('y', 28)
      .attr('fill', '#d1d5db')
      .attr('font-size', 10)
      .text((d) => d.label);

    sim.on('tick', () => {
      link
        .attr('x1', (d) => d.source.x)
        .attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x)
        .attr('y2', (d) => d.target.y);
      node.attr('transform', (d) => `translate(${d.x},${d.y})`);
    });

    return () => sim.stop();
  }, []);

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">Network Map</h2>
        <div className="flex gap-3 text-xs">
          {Object.entries(THREAT_COLOR).map(([k, c]) => (
            <span key={k} className="flex items-center gap-1.5 capitalize" style={{ color: c }}>
              <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ backgroundColor: c }} />
              {k}
            </span>
          ))}
        </div>
      </div>
      <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden" style={{ height: 520 }}>
        <svg ref={svgRef} className="w-full h-full" />
      </div>
      <p className="text-xs text-gray-500 text-center">Drag nodes to rearrange · Scroll to zoom</p>
    </div>
  );
}
