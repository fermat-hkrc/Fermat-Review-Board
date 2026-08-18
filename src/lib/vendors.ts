export const VENDORS: Record<string, { label: string; color: string }> = {
  public: { label: "Open Source", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  cbg: { label: "Business Group", color: "bg-violet-500/20 text-violet-400 border-violet-500/30" },
};

export const DEFAULT_VENDOR = "public";

export function getVendorLabel(key: string): string {
  return VENDORS[key]?.label || key;
}

export function getVendorColor(key: string): string {
  return VENDORS[key]?.color || "bg-gray-500/20 text-gray-400 border-gray-500/30";
}
