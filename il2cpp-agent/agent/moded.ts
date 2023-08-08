function hookHack() {
  let rewriteFunction: any = {};
  let config = {
    cameraHight: false && 150,
    hackSeeAll: true,
    hackOpenGrass: true,
    hackCeilBuilding: true,
    hackViewTypePlayer: true,
    gameMode: "",
  };
  var AssemblyCSharp: Il2Cpp.Image;
  let playerUID: Il2Cpp.String = Il2Cpp.String.from(null);
  let playerId: number = -1;

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
      function openAllGrass(
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
      function viewTypePlayer(this: Il2Cpp.Object | Il2Cpp.Class) {
        let name = this.method<Il2Cpp.String>("GetLocalizedName").invoke();
        if (config.hackViewTypePlayer)
          name.content += this.method<boolean>("get_IsBot").invoke()
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
      "MetagamePlayerCache",
      "get_MaxLeague",
      function (this: Il2Cpp.Object | Il2Cpp.Class) {
        if (playerUID.isNull()) {
          this.method<Il2Cpp.String>("get_PublicId").invoke();
          console.log(`playerUID=${playerUID}`);
        }
        return this.method("get_MaxLeague").invoke();
      }
    );
  }

  let GameplayViewController: null | Il2Cpp.Object | Il2Cpp.Class = null;
  let GameplayView: null | Il2Cpp.Object | Il2Cpp.Class = null;
  let PlayerController: null | Il2Cpp.Object | Il2Cpp.Class = null;

  let needUseMedkit = false;
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
  function findCurrentPlayerController() {
    let klas = AssemblyCSharp.class("PlayerController");
    klas.method("get_IsGuard").implementation = function (
      this: Il2Cpp.Class | Il2Cpp.Object
    ) {
      if (PlayerController == null) {
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
    klas.method("<SetupView>b__95_3").implementation = function (
      this: Il2Cpp.Object | Il2Cpp.Class
    ) {
      this.method("<SetupView>b__95_3").invoke();
      //On hook after run match do this for get user id
      OnMatchStartRunningSetup(this);
    };
    klas.method("OnMatchStartRunning").implementation = function (
      this: Il2Cpp.Object | Il2Cpp.Class,
      isServer: boolean
    ) {
      OnMatchStartRunningSetup(this);
      return this.method("OnMatchStartRunning").invoke(isServer);
    };
    klas.method("OnMatchEnded").implementation = function (
      this: Il2Cpp.Object | Il2Cpp.Class,
      matchEndedData: any,
      isServer: boolean
    ) {
      OnMatchEndedSetup();
      return this.method("OnMatchEnded").invoke(matchEndedData, isServer);
    };
    klas.method("OnMatchFinished").implementation = function (
      this: Il2Cpp.Object | Il2Cpp.Class,
      OnMatchFinished: any
    ) {
      OnMatchFinishedSetup();
      return this.method("OnMatchFinished").invoke(OnMatchFinished);
    };
    klas.method("Destroy").implementation = function (
      this: Il2Cpp.Object | Il2Cpp.Class
    ) {
      GameplayViewController = null;
      return this.method("Destroy").invoke();
    };
  }
  function OnMatchStartRunningSetup(
    GamePlayViewControllerInstance: Il2Cpp.Object | Il2Cpp.Class
  ) {
    //Khi load map xong
    if (!GameplayViewController)
      GameplayViewController = GamePlayViewControllerInstance;
    if (!GameplayView)
      GameplayView = GamePlayViewControllerInstance.method(
        "GetView"
      ).invoke() as Il2Cpp.Object;
    if (playerId < 0)
      playerId =
        GamePlayViewControllerInstance.field<number>("_mainPlayerId").value;
    if (!playerUID) {
      let playerCache = GamePlayViewControllerInstance.field("_playerCache")
        .value as Il2Cpp.Object;
      playerCache.method("get_PublicId").invoke();
    }
  }

  function OnMatchEndedSetup() {
    //Khi người chơi chính bị chết
    PlayerController = null;
    playerId = -1;
    GameplayView = null;
    needUseMedkit = false;
  }
  function OnMatchFinishedSetup() {
    //Khi trận đầu xong hết
    PlayerController = null;
    playerId = -1;
    GameplayView = null;
  }

  function autoHealth() {
    addRewriteMethodAssemblyCSharp(
      "GameplayView",
      "Update",
      function (this: Il2Cpp.Object) {
        if (GameplayView === null) {
          GameplayView = this;
          needUseMedkit = false;
        }
        if (
          needUseMedkit &&
          this.method<boolean>("UseOrTriggerMedKit").invoke()
        ) {
          needUseMedkit = false;
        }
        this.method("Update").invoke();
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
  AssemblyCSharp = Il2Cpp.Domain.assembly("Assembly-CSharp").image;
  getUserUID();
  hackViewTypePlayer();
  hackCamera();
  hackCeilBuilding();
  hackSeeAll();
  hackGrass();
  hookGameplayViewController();
  findCurrentPlayerController();
  autoHealth();
  hookGameMode();
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

export { hookHack };
