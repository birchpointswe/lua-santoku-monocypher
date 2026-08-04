local env = {
  name = "santoku-monocypher",
  version = "1.2.0-1",
  license = "MIT",
  public = true,
  cflags = {
    "-I$(shell luarocks show santoku --rock-dir)/include/",
  },
  ldflags = {},
  dependencies = {
    "lua == 5.1",
    "santoku >= 1.0.0, < 2.0.0"
  },
}

env.homepage = "https://github.com/birchpointswe/lua-" .. env.name
env.tarball = env.name .. "-" .. env.version .. ".tar.gz"
env.download = env.homepage .. "/releases/download/" .. env.version .. "/" .. env.tarball

return { env = env }
