import "frida-il2cpp-bridge";

const viewGrass = true;
const viewEnermy = true;
const viewInsightBuilding = true;
const zoomFactor = 4;

const classes = [
  //"MatchReferee",
  "SROptionsQA",
  "BattleRoyale.Configs.PlayerPreferences","MatchMaker"
  // "BasePlayerRendererGrassRingController",
];
const methods = [
  "FixedUpdateLoop",
  "get_TicksSinceMatchStarted",
  "get_StartTick",
  "get_TicksToStartMatch",
  "OnDeserialize",
];
let AssemblyCSharp: Il2Cpp.Image;
Il2Cpp.perform(() => {
  setTimeout(() => {
    Il2Cpp.trace()
      .assemblies(Il2Cpp.Domain.assembly("Assembly-CSharp"))
      .filterClasses((cls) => classes.includes(cls.name))
      .filterMethods((mtd) => !methods.includes(mtd.name))
      .and()
      .attach("detailed");

    AssemblyCSharp = Il2Cpp.Domain.assembly("Assembly-CSharp").image;

    hackGrass();
    hackViewAll();
    hackCeil();
    hackcamera();
    testHack();
  }, 0.1 * 1000); // we sleep 10 seconds so the application doesn't crash on attach
});
function hackGrass() {
  const BasePlayerRendererGrassRingController = AssemblyCSharp.class(
    "BasePlayerRendererGrassRingController"
  );
  const UpdatePlayerGrassCircleRadius =
    BasePlayerRendererGrassRingController.method(
      "UpdatePlayerGrassCircleRadius"
    );
  UpdatePlayerGrassCircleRadius.implementation = function (
    this: Il2Cpp.Object | Il2Cpp.Class,
    radius: number,
    roundPercent01: number
  ): void {
    if (viewGrass) radius = 10000;
    this.method<void>("UpdatePlayerGrassCircleRadius").invoke(
      radius,
      roundPercent01
    );
  };
}
function hackViewAll() {
  const VisibilityController = AssemblyCSharp.class("VisibilityController");
  const IsSameTeam = VisibilityController.method("IsSameTeam");
  IsSameTeam.implementation = function (
    this: Il2Cpp.Object | Il2Cpp.Class,
    him
  ): boolean {
    if (viewEnermy) return true;
    return this.method<boolean>("IsSameTeam").invoke(him);
  };
}
function hackCeil() {
  const BuildingCeilController = AssemblyCSharp.class(
    "TFG.GFX.BuildingCeilController"
  );
  // Il2Cpp.trace()
  //   .classes(BuildingCeilController)
  //   .filterMethods((mtd) => !mtd.name.includes("UpdateOpacity"))
  //   .and()
  //   .attach("full");
  const UpdateOpacity = BuildingCeilController.method("UpdateOpacity");

  UpdateOpacity.implementation = function (
    this: Il2Cpp.Object | Il2Cpp.Class
  ): void {
    if (viewInsightBuilding) {
      this.method<void>("CeilCameraVisible").invoke(false);
    }
    this.method<void>("UpdateOpacity").invoke();
  };
}
function hackcamera() {
  const GameplayCameraController = AssemblyCSharp.class(
    "GameplayCameraController"
  );

  const LateUpdate = GameplayCameraController.method("LateUpdate");

  LateUpdate.implementation = function (
    this: Il2Cpp.Object | Il2Cpp.Class
  ): void {
    if (zoomFactor >= 1) {
      this.method<void>("set_CurrentTargetZoom").invoke(150);
    }
    this.method<void>("LateUpdate").invoke();
  };
}
function testHack() {
  const get_RoomRegion =
    AssemblyCSharp.class("MatchReferee").method("get_RoomRegion");
  const get_AutoRegion = AssemblyCSharp.class(
    "BattleRoyale.Configs.PlayerPreferences"
  ).method("get_AutoRegion");

  get_AutoRegion.implementation = function (this): Il2Cpp.String {
    let rg = this.method("get_AutoRegion").invoke();
    console.log(`rg: ${rg}`);
    //
    return Il2Cpp.String.from("china");
  };

  get_RoomRegion.implementation = function (this) {
    let rg = this.method("get_RoomRegion").invoke();
    console.log(`rrg: ${rg}`);
    return rg;
  };
}
