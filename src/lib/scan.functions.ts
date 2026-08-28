import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

export const scanNetwork = createServerFn({ method: "POST" })
  .inputValidator((data) => z.object({ host: z.string().min(3).max(255) }).parse(data))
  .handler(async ({ data }) => {
    const { runScan } = await import("./scan.server");
    return runScan(data.host);
  });
