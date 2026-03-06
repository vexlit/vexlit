import Image from "next/image";

export function VexlitLogo({ size = 24 }: { size?: number }) {
  return (
    <Image
      src="/vexlit.svg"
      alt="VEXLIT"
      width={size}
      height={size}
      className="shrink-0"
    />
  );
}
