import "frida-il2cpp-bridge";

const viewGrass = true;
const viewEnermy = true;
const viewInsightBuilding = true;
const zoomFactor = 0;
let InventorySlotType: Il2Cpp.Class;

function maketoast(message: string) {
  Java.perform(function () {
    var context = Java.use("android.app.ActivityThread")
      .currentApplication()
      .getApplicationContext();

    Java.scheduleOnMainThread(function () {
      var toast = Java.use("android.widget.Toast");
      toast
        .makeText(context, Java.use("java.lang.String").$new(message), 1)
        .show();
    });
  });
}
function hookHack() {
  InventorySlotType =
    Il2Cpp.Domain.assembly("Assembly-CSharp").image.class("InventorySlotType");

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

  // console.log(`assemblies: ${assembliess}`);
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

  for (let Assembly in rewriteFunction) {
    const classes: any = rewriteFunction[Assembly];
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

function chooseMod(
  this: any,
  gameMode: any,
  isPayingEnergy: any,
  success: any,
  failure: any
) {
  console.log(`gameMode: ${gameMode}`);
  // const newMode = Il2Cpp.String.from("arena_04_solostd");
  // console.log(`newMode: ${newMode}`);
  return this.method("FindMatch").invoke(
    gameMode,
    isPayingEnergy,
    success,
    failure
  );
}
function openAllGrass(
  this: Il2Cpp.Object | Il2Cpp.Class,
  radius: number,
  roundPercent01: number
): void {
  if (viewGrass) radius = 10000;
  this.method<void>("UpdatePlayerGrassCircleRadius").invoke(
    radius,
    roundPercent01
  );
}
function viewTypePlayer(this: Il2Cpp.Object | Il2Cpp.Class) {
  let name = this.method<Il2Cpp.String>("GetLocalizedName").invoke().toString();

  name += this.method<boolean>("get_IsBot").invoke() ? " - bot" : " - player";

  return Il2Cpp.String.from(name);
}
function droneCamera(this: Il2Cpp.Object | Il2Cpp.Class): void {
  if (zoomFactor >= 1) {
    this.method<void>("set_CurrentTargetZoom").invoke(150);
  }
  this.method<void>("LateUpdate").invoke();
}
function hackCeilBuilding(this: Il2Cpp.Object | Il2Cpp.Class): void {
  if (viewInsightBuilding) {
    this.method<void>("CeilCameraVisible").invoke(false);
  }
  this.method<void>("UpdateOpacity").invoke();
}
function hackGrass(this: Il2Cpp.Object | Il2Cpp.Class, him: any): boolean {
  if (viewEnermy) return true;
  return this.method<boolean>("IsSameTeam").invoke(him);
}
let playerId: Il2Cpp.String = Il2Cpp.String.from(null);
function getUserId(this: Il2Cpp.Object | Il2Cpp.Class) {
  playerId = this.method<Il2Cpp.String>("get_PublicId").invoke();
  return playerId;
}
let PlayerController: Il2Cpp.Object | Il2Cpp.Class | null = null;
let GameplayView: Il2Cpp.Class | Il2Cpp.Object | null = null;

function getPlayerControllerFieldObject(
  controllerName:
    | string
    | "GameInventoryController"
    | "HealthController"
    | "DamageController"
    | "MovementController"
    | "VisibilityController"
    | "PlayerStatusController"
) {
  if (PlayerController === null) {
    return null;
  }
  return PlayerController.field(controllerName).value as Il2Cpp.Object;
}
const rewriteFunction: any = {
  "Assembly-CSharp": {
    MatchmakingClient: { FindMatch: chooseMod },
    BasePlayerRendererGrassRingController: {
      UpdatePlayerGrassCircleRadius: openAllGrass,
    },
    GameplayViewController: {
      OnMatchEnded: function (
        this: Il2Cpp.Object | Il2Cpp.Class,
        matchEndedData: any,
        isServer: boolean
      ) {
        this.method("OnMatchEnded").invoke(matchEndedData, isServer);
        PlayerController = null;
        GameplayView = null;
        console.log("set PlayerController = null");
      },
    },
    GameplayView: {
      Update: function (this: Il2Cpp.Object) {
        if (GameplayView === null) GameplayView = this;
        this.method("Update").invoke();
      },
    },
    PlayerController: {
      GetLocalizedName: viewTypePlayer,
      get_IsBot: function (this: Il2Cpp.Object | Il2Cpp.Class) {
        if (PlayerController == null) {
          let classPlayerProfile = this.field("_playerProfile")
            .value as Il2Cpp.Object;
          let playerUID = classPlayerProfile
            .method<Il2Cpp.String>("get_PlayerId")
            .invoke();
          console.log(`PlayerController == null: ${playerUID} --> ${playerId}`);

          if (playerUID.content === playerId.content) {
            console.log("playerUID === playerId");
            PlayerController = this;
            let currentHealth = getPlayerControllerFieldObject(
              "HealthController"
            )
              ?.method<number>("get_CurrentHealth")
              .invoke();
            console.log(`currentHealth=${currentHealth}`);
          }
        }
        return this.method("get_IsBot").invoke();
      },
    },
    GameplayCameraController: { LateUpdate: droneCamera },
    "TFG.GFX.BuildingCeilController": { UpdateOpacity: hackCeilBuilding },
    VisibilityController: { IsSameTeam: hackGrass },
    MetagamePlayerCache: {
      get_PublicId: getUserId,
      get_MaxLeague: function (this: Il2Cpp.Object | Il2Cpp.Class) {
        if (playerId.isNull()) {
          playerId = this.method<Il2Cpp.String>("get_PublicId").invoke();
        }
        return this.method("get_MaxLeague").invoke();
      },
    },
    GameInventoryController: {},
    HealthController: {
      NotifyObservers: function (
        this: Il2Cpp.Object | Il2Cpp.Class,
        deltaHealth: number,
        deltaShield: number,
        origin: any,
        attacker: any,
        isCritical: boolean
      ) {
        let myH = getPlayerControllerFieldObject("HealthController");
        if (myH && this.equals(myH)) {
          console.log("myH=this");
          let currentHealth = this.method<number>("get_CurrentHealth").invoke();
          console.log(
            `currentHealth=${currentHealth} ---> deltaHealth=${deltaHealth}`
          );
          if (currentHealth < 300 || currentHealth - deltaHealth <= 0) {
            //TODO: Use health kit
            GameplayView?.method("UseOrTriggerMedKit").invoke();
          }
        }
        this.method("NotifyObservers").invoke(
          deltaHealth,
          deltaShield,
          origin,
          attacker,
          isCritical
        );
      },
    },
  },
  Protos: {},
};
const traces: any = {
  IsRun: !true,
  Assemblies: ["Assembly-CSharp"],
  Classes: ["GameInventoryController"],
  All: false,
  UsingIncludes: !false,
  MethodIncludes: ["UseSkillInSlot"],
  MethodExcludes: ["OnDeserialize", "NotifyObservers"],
  ignoreMethodContainsKeyword: [
    "isGuard",
    // "GetLocalizedName",
    "IsChild",
    "IsDead",
    "UpdateLoop",
    "IsOnGround",
    "get_Invincible",
    "update",
    // "SetupView",
    // "OnSomeoneDies",
    // "count",
  ],
  mode: !"full" || "detailed",
};

function testHack() {
  // const assembly = Il2Cpp.Domain.assembly("Assembly-CSharp").image;
  // const klas = assembly.class("MetagamePlayerCache");
  // const method = klas.method("get_Player");
  // const player = method.invoke() as Il2Cpp.Object;
  // let playerId = player.method("get_PublicId").invoke();
  // console.log(`playerId= ${playerId}`);
}
Il2Cpp.perform(() => {
  setTimeout(() => {
    maketoast("Moded by KhangPQ");
    hookHack();
    testHack();
  }, 100);
});
