import "frida-il2cpp-bridge";

function hookHack() {
  let rewriteFunction: any = {};
  let config = {
    cameraHight: 0 && 150,
    hackSeeAll: true,
    hackOpenGrass: true,
    hackCeilBuilding: true,
    hackViewTypePlayer: true,
    gameMode: "trio",
  };
  var AssemblyCSharp: Il2Cpp.Image;
  let playerUID: Il2Cpp.String = Il2Cpp.String.from(null);
  let playerId = -1;
  let needUseMedkit = false;
  let endgame = false;
  let PlayerController: null | Il2Cpp.Object | Il2Cpp.Class = null;
  AssemblyCSharp = Il2Cpp.Domain.assembly("Assembly-CSharp").image;

  function addRewriteMethod(
    assembly: string | "Assembly-CSharp",
    className: string,
    methodName: string,
    rewriteFunc: any
  ) {
    if (!rewriteFunction[assembly]) {
      rewriteFunction[assembly] = {};
    }
    if (!rewriteFunction[assembly][className]) {
      rewriteFunction[assembly][className] = {};
    }
    rewriteFunction[assembly][className][methodName] = rewriteFunc;
  }

  function addRewriteMethodAssemblyCSharp(
    className: string,
    methodName: string,
    rewriteFunc: any
  ) {
    addRewriteMethod("Assembly-CSharp", className, methodName, rewriteFunc);
  }

  function hackSeeAll() {
    addRewriteMethodAssemblyCSharp(
      "VisibilityController",
      "IsSameTeam",
      function (this: Il2Cpp.Object | Il2Cpp.Class, him: any) {
        return config.hackSeeAll || this.method("IsSameTeam").invoke(him);
      }
    );
  }

  function hackGrass() {
    addRewriteMethodAssemblyCSharp(
      "BasePlayerRendererGrassRingController",
      "UpdatePlayerGrassCircleRadius",
      function (
        this: Il2Cpp.Object | Il2Cpp.Class,
        radius: number,
        roundPercent01: number
      ): void {
        this.method<void>("UpdatePlayerGrassCircleRadius").invoke(
          config.hackOpenGrass ? 10000 : radius,
          roundPercent01
        );
      }
    );
  }

  function hackCeilBuilding() {
    addRewriteMethodAssemblyCSharp(
      "TFG.GFX.BuildingCeilController",
      "UpdateOpacity",
      function (this: Il2Cpp.Object | Il2Cpp.Class): void {
        if (config.hackCeilBuilding)
          this.method<void>("CeilCameraVisible").invoke(false);
        this.method<void>("UpdateOpacity").invoke();
      }
    );
  }

  function hackCamera() {
    addRewriteMethodAssemblyCSharp(
      "GameplayCameraController",
      "LateUpdate",
      function (this: Il2Cpp.Object | Il2Cpp.Class): void {
        if (config.cameraHight) {
          this.method<void>("set_CurrentTargetZoom").invoke(config.cameraHight);
        }
        this.method<void>("LateUpdate").invoke();
      }
    );
  }

  function hackViewTypePlayer() {
    addRewriteMethodAssemblyCSharp(
      "PlayerController",
      "GetLocalizedName",
      function (this: Il2Cpp.Object | Il2Cpp.Class) {
        let name = this.method<Il2Cpp.String>("GetLocalizedName").invoke();
        if (config.hackViewTypePlayer)
          name.content += this.field<boolean>("_isBot").value
            ? " - bot"
            : " - player";
        return name;
      }
    );
  }

  function getUserUID() {
    addRewriteMethodAssemblyCSharp(
      "MetagamePlayerCache",
      "get_PublicId",
      function (this: Il2Cpp.Object | Il2Cpp.Class) {
        playerUID = this.method<Il2Cpp.String>("get_PublicId").invoke();
        return playerUID;
      }
    );
    addRewriteMethodAssemblyCSharp(
      "Player",
      "Save",
      function (
        this: Il2Cpp.Object | Il2Cpp.Class,
        accessToken: Il2Cpp.String,
        PublicId: Il2Cpp.String
      ) {
        playerUID = PublicId;
        console.log(`Save player ${playerUID}`);
        return this.method("Save").invoke(accessToken, PublicId);
      }
    );
  }

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
  // async function setUser(params:type) {

  // }
  function findCurrentPlayerController() {
    let klas = AssemblyCSharp.class("PlayerController");
    klas.method("get_IsGuard").implementation = function (
      this: Il2Cpp.Class | Il2Cpp.Object
    ) {
      if (PlayerController == null && playerUID.content) {
        let classPlayerProfile = this.field("_playerProfile")
          .value as Il2Cpp.Object;
        let playerUID1 = classPlayerProfile
          .method<Il2Cpp.String>("get_PlayerId")
          .invoke();
        console.log(`PlayerController == null: ${playerUID} --> ${playerUID1}`);

        if (playerUID.content === playerUID1.content) {
          console.log("playerUID === playerId");
          PlayerController = this;
        }
      }

      return this.method("get_IsGuard").invoke();
    };
  }
  function hookGameplayViewController() {
    let klas = AssemblyCSharp.class("GameplayViewController");

    klas.method("OnMatchStartRunning").implementation = function (
      this: Il2Cpp.Object | Il2Cpp.Class,
      isServer: boolean
    ) {
      playerId = this.field<number>("_mainPlayerId").value;
      this.method("OnMatchStartRunning").invoke(isServer);
      setTimeout(async () => {
        needUseMedkit = false;
        endgame = false;
      }, 0);
    };

    klas.method("OnMatchEnded").implementation = function (
      this: Il2Cpp.Object | Il2Cpp.Class,
      matchEndedData: any,
      isServer: boolean
    ) {
      this.method("OnMatchEnded").invoke(matchEndedData, isServer);
      setTimeout(async () => {
        needUseMedkit = false;
        endgame = true;
      }, 0);
    };
    // klas.method("OnMatchFinished").implementation = function (
    //   this: Il2Cpp.Object | Il2Cpp.Class,
    //   matchFinishedData: any
    // ) {
    //   this.method("OnMatchFinished").invoke(matchFinishedData);
    // };
  }

  function autoHealth() {
    addRewriteMethodAssemblyCSharp(
      "GameplayView",
      "FixedUpdate",
      function (this: Il2Cpp.Object) {
        if (needUseMedkit && !endgame) {
          needUseMedkit = !this.method<boolean>("UseOrTriggerMedKit").invoke();
        }
        this.method("FixedUpdate").invoke();
      }
    );
    addRewriteMethodAssemblyCSharp(
      "HealthController",
      "NotifyObservers",
      function (
        this: Il2Cpp.Object | Il2Cpp.Class,
        deltaHealth: number,
        deltaShield: number,
        origin: any,
        attacker: any,
        isCritical: boolean
      ) {
        let myH = getPlayerControllerFieldObject("HealthController");
        if (myH && this.equals(myH)) {
          let currentHealth = this.method<number>("get_CurrentHealth").invoke();
          console.log(
            `myH=this: currentHealth=${currentHealth} ---> deltaHealth=${deltaHealth}`
          );
          if (currentHealth < 300 || currentHealth - deltaHealth <= 0) {
            console.log(`Need Use MedKit`);
            needUseMedkit = true;
          }
        }
        this.method("NotifyObservers").invoke(
          deltaHealth,
          deltaShield,
          origin,
          attacker,
          isCritical
        );
      }
    );
  }

  function hookGameMode() {
    addRewriteMethodAssemblyCSharp(
      "MatchmakingClient",
      "FindMatch",
      function (
        this: Il2Cpp.Object | Il2Cpp.Class,
        gameMode: any,
        isPayingEnergy: any,
        success: any,
        failure: any
      ) {
        if (config.gameMode) {
          gameMode = Il2Cpp.String.from(config.gameMode);
        }
        console.log(`Selected gameMode: ${gameMode}`);
        return this.method("FindMatch").invoke(
          gameMode,
          isPayingEnergy,
          success,
          failure
        );
      }
    );
  }

  ////////////////////////////////////////////////////////////////////////////////////////////////
  getUserUID();
  hackViewTypePlayer();
  hackCamera();
  hackCeilBuilding();
  hackSeeAll();
  hackGrass();
  hookGameMode();
  hookGameplayViewController();
  findCurrentPlayerController();
  autoHealth();
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
  console.log(`Done Hooking`);
}

export { hookHack };
