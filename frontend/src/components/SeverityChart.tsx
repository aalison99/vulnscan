import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import type { SeverityCounts } from '../types'
import { SEVERITY_HEX, SEVERITY_ORDER, countFor } from '../lib'

export default function SeverityChart({ counts }: { counts: SeverityCounts }) {
  const rows = SEVERITY_ORDER.map((s) => ({ name: s, value: countFor(counts, s) }))
  const data = rows.filter((r) => r.value > 0)
  const total = data.reduce((a, r) => a + r.value, 0)
  const legend = rows.filter((r) => r.name !== 'UNKNOWN' || r.value > 0)

  if (total === 0) {
    return (
      <div className="flex h-56 items-center justify-center text-sm text-slate-500">
        No vulnerabilities recorded yet
      </div>
    )
  }

  return (
    <div className="flex flex-col items-center gap-6 sm:flex-row">
      <div className="relative h-56 w-56 shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={65}
              outerRadius={95}
              paddingAngle={2}
              stroke="none"
            >
              {data.map((d) => (
                <Cell key={d.name} fill={SEVERITY_HEX[d.name]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: '#111722',
                border: '1px solid #252f42',
                borderRadius: 8,
                color: '#e2e8f0',
                fontSize: 12,
              }}
              itemStyle={{ color: '#e2e8f0' }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-2xl font-semibold text-white">{total}</div>
          <div className="text-xs text-slate-500">total</div>
        </div>
      </div>

      <ul className="w-full space-y-3">
        {legend.map((r) => (
          <li key={r.name}>
            <div className="mb-1 flex items-center justify-between text-sm">
              <span className="flex items-center gap-2 text-slate-300">
                <span
                  className="h-2.5 w-2.5 rounded-full"
                  style={{ background: SEVERITY_HEX[r.name] }}
                />
                {r.name.charAt(0) + r.name.slice(1).toLowerCase()}
              </span>
              <span className="font-mono text-slate-400">{r.value}</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-ink-700">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${(r.value / total) * 100}%`,
                  background: SEVERITY_HEX[r.name],
                }}
              />
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}