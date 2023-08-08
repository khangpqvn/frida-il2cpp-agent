import "frida-il2cpp-bridge";
import { utils } from "./utils";
import { hookHack as moded } from "./moded";

function hookHack() {
  function calculateMethodFilter(name: string): boolean {
    name = name.toLowerCase();
    for (let i = 0; i < traces.ignoreMethodContainsKeyword.length; i++) {
      const keyword = traces.ignoreMethodContainsKeyword[i].toLowerCase();
      if (name.includes(keyword)) {
        return false;
      }
    }
    if (traces.UsingIncludes) {
      for (let i = 0; i < traces.MethodIncludes.length; i++) {
        const method = traces.MethodIncludes[i].toLowerCase();
        if (name === method) {
          return true;
        }
      }
      return false;
    } else {
      for (let i = 0; i < traces.MethodExcludes.length; i++) {
        const method = traces.MethodExcludes[i].toLowerCase();
        if (name === method) {
          return false;
        }
      }
      return true;
    }
  }

  let rewriteFunc: any = rewriteFunction();
  if (traces.IsRun)
    traces.Assemblies.forEach((assemb: any) => {
      console.log(`Traces: ${assemb}`);
      Il2Cpp.trace()
        .assemblies(Il2Cpp.Domain.assembly(assemb))
        .filterClasses((cls: any) => {
          return traces.Classes.map((v: string) => v.toLowerCase()).includes(
            cls.name.toLowerCase()
          );
        })
        .filterMethods((mtd: Il2Cpp.Method) => {
          return traces.All || calculateMethodFilter(mtd.name);
        })
        .and()
        .attach(traces.mode);
    });

  for (let Assembly in rewriteFunc) {
    const classes: any = rewriteFunc[Assembly];
    const assembly = Il2Cpp.Domain.assembly(Assembly).image;
    for (let klasss in classes) {
      const methods = classes[klasss];
      const klas = assembly.class(klasss);
      for (const mt in methods) {
        klas.method(mt).implementation = methods[mt];
      }
    }
  }
}
const traces: any = {
  IsRun: true,
  Assemblies: ["Assembly-CSharp", "Protos"],
  Classes: ["Player"],
  All: false,
  UsingIncludes: false,
  MethodIncludes: [],
  MethodExcludes: [
    // "GetSlotsWithCategory",
    // "GetLastWeaponUsed",
    // "HasSkillInSlot",
    // "GetSkillInSlot",
    // "HasFreeSlotOfCategory",
    // "GetAnySkillProfile",
    // "TryGetSkillInSlot",
    // "SupportsCategory",
    // "InventoryPossibleExchange",
    // "InventoryForceExchange",
    // "GetCooldownTimePercentLeft",
    // "CanUseSkill",
    // "GetActiveCooldownTimePercentLeft",
  ],
  ignoreMethodContainsKeyword: ["update", "getAny", "SetupView"],
  mode: !"full" || "detailed",
};
function rewriteFunction() {
  return {
    "Assembly-CSharp": {},
    Protos: {},
  };
}

Il2Cpp.perform(() => {
  setTimeout(() => {
    utils.toast("Moded by KhangPQ");
    moded();
    hookHack();
  }, 100);
});
