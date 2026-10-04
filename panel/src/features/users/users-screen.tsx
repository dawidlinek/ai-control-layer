"use client";

import * as React from "react";
import { debounce, parseAsInteger, parseAsString, parseAsStringLiteral, useQueryState } from "nuqs";
import {
  FilterMenuButton,
  FilterRow,
  FilterSpacer,
  PageHeader,
  SearchInput,
  SegmentedTabs,
  useSelectedId,
} from "@/components/rogatka";
import { LoadedOfTotal } from "@/lib/api/loaded-of-total";
import { useGroups, useUsers } from "./api";
import { GroupsTab } from "./groups";
import { KeycloakLink } from "./keycloak";
import { PeopleTab } from "./people";

const TABS = ["people", "groups"] as const;
export function UsersScreen() {
  const [tab, setTab] = useQueryState("tab", parseAsStringLiteral(TABS).withDefault("people"));
  const [, setSel] = useSelectedId();
  const [q, setQ] = useQueryState("q", parseAsString.withDefault("").withOptions({ limitUrlUpdates: debounce(300) }));
  const [group, setGroup] = useQueryState("group", parseAsString);
  const [risk, setRisk] = useQueryState("risk", parseAsStringLiteral(["blocks"] as const));
  const [, setPage] = useQueryState("page", parseAsInteger);
  const users = useUsers();
  const groups = useGroups();
  const people = (users.data ?? []).filter((u) => u.kind === "user");

  return (
    <div className="flex flex-col gap-3.5">
      <PageHeader title="Users & groups" actions={<KeycloakLink label="Open Keycloak" />} />
      <FilterRow>
        <SegmentedTabs
          ariaLabel="View"
          value={tab}
          onChange={(t) => {
            void setTab(t === "people" ? null : t);
            void setSel(null);
            void setPage(null);
          }}
          tabs={[
            { value: "people", label: "People", count: users.data ? people.length : undefined },
            { value: "groups", label: "Groups", count: groups.data ? groups.data.length : undefined },
          ]}
        />
        {tab === "people" && (
          <>
            <FilterMenuButton
              label="Group"
              multiple={false}
              options={(groups.data ?? []).map((g) => ({ value: g.name, label: g.name }))}
              selected={group ? [group] : []}
              onChange={(v) => {
                void setGroup(v[0] ?? null);
                void setPage(null);
              }}
            />
            <FilterMenuButton
              label="Risk"
              multiple={false}
              options={[{ value: "blocks", label: "Blocked in the last 7 days" }]}
              selected={risk ? [risk] : []}
              onChange={(v) => {
                void setRisk(v[0] === "blocks" ? "blocks" : null);
                void setPage(null);
              }}
            />
          </>
        )}
        <FilterSpacer />
        <SearchInput
          value={q}
          onChange={(v) => {
            void setQ(v || null);
            void setPage(null);
          }}
          placeholder={tab === "people" ? "Name or e-mail" : "Group name"}
          ariaLabel="Search people or groups"
        />
      </FilterRow>
      {tab === "people" ? (
        <>
          <PeopleTab users={users} groups={groups.data ?? []} q={q} group={group} risk={risk} />
          <LoadedOfTotal loaded={users.data?.length ?? 0} total={users.total} noun="people and agents" />
        </>
      ) : (
        <GroupsTab groups={groups} q={q} />
      )}
    </div>
  );
}
