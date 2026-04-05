import { and, eq, gt, isNull, or } from "drizzle-orm";
import { db } from "../db/client.js";
import { vaultItems, type VaultItem } from "../db/schema.js";
import { notFound } from "../lib/errors.js";

export type VaultItemDTO = {
  id: string;
  encryptedData: string; // base64
  nonce: string; // base64
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
};

function toDTO(row: VaultItem): VaultItemDTO {
  return {
    id: row.id,
    encryptedData: row.encryptedData.toString("base64"),
    nonce: row.nonce.toString("base64"),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    deletedAt: row.deletedAt ? row.deletedAt.toISOString() : null,
  };
}

/**
 * List vault items for a user.
 * - When `since` is omitted: returns all non-deleted items (initial sync / cold start).
 * - When `since` is provided: returns every item whose updatedAt > since, INCLUDING soft-deleted
 *   ones, so the client can propagate deletions.
 */
export async function listItems(userId: string, since?: Date): Promise<VaultItemDTO[]> {
  const rows = since
    ? await db
        .select()
        .from(vaultItems)
        .where(and(eq(vaultItems.userId, userId), gt(vaultItems.updatedAt, since)))
    : await db
        .select()
        .from(vaultItems)
        .where(and(eq(vaultItems.userId, userId), isNull(vaultItems.deletedAt)));
  return rows.map(toDTO);
}

export async function createItem(
  userId: string,
  encryptedData: Buffer,
  nonce: Buffer,
): Promise<VaultItemDTO> {
  const [row] = await db
    .insert(vaultItems)
    .values({ userId, encryptedData, nonce })
    .returning();
  return toDTO(row!);
}

export async function updateItem(
  userId: string,
  itemId: string,
  encryptedData: Buffer,
  nonce: Buffer,
): Promise<VaultItemDTO> {
  const [row] = await db
    .update(vaultItems)
    .set({ encryptedData, nonce, updatedAt: new Date() })
    .where(
      and(
        eq(vaultItems.id, itemId),
        eq(vaultItems.userId, userId),
        isNull(vaultItems.deletedAt),
      ),
    )
    .returning();
  if (!row) throw notFound("Vault item not found");
  return toDTO(row);
}

export async function softDeleteItem(userId: string, itemId: string): Promise<void> {
  const now = new Date();
  const [row] = await db
    .update(vaultItems)
    .set({ deletedAt: now, updatedAt: now })
    .where(
      and(
        eq(vaultItems.id, itemId),
        eq(vaultItems.userId, userId),
        isNull(vaultItems.deletedAt),
      ),
    )
    .returning({ id: vaultItems.id });
  if (!row) throw notFound("Vault item not found");
}
