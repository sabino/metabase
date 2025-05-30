import { t } from "ttag";

export const DEFAULT_COLLECTION_COLOR_ALIAS = "brand";

export const ROOT_COLLECTION = {
  id: "root" as const,
  get name() {
    return t`Our analytics`;
  },
  location: "",
  path: [],
  is_personal: false,
};

export const PERSONAL_COLLECTION = {
  id: undefined, // to be filled in by getExpandedCollectionsById
  get name() {
    return t`My personal collection`;
  },
  location: "/",
  path: [ROOT_COLLECTION.id],
  can_write: true,
  is_personal: true,
};

// fake collection for admins that contains all other user's collections
export const PERSONAL_COLLECTIONS = {
  id: "personal" as const, // placeholder id
  get name() {
    return t`All personal collections`;
  },
  location: "/",
  path: [ROOT_COLLECTION.id],
  can_write: false,
  is_personal: true,
};
