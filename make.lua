local env = {
  name = "santoku-monocypher",
  version = "0.0.13-1",
  license = "MIT",
  public = true,
  cflags = {
    "-I$(shell luarocks show santoku --rock-dir)/include/",
  },
  ldflags = {},
  dependencies = {
    "lua == 5.1",
    "santoku >= 0.0.316-1"
  },
}

env.homepage = "https://github.com/treadwelllane/lua-" .. env.name
env.tarball = env.name .. "-" .. env.version .. ".tar.gz"
env.download = env.homepage .. "/releases/download/" .. env.version .. "/" .. env.tarball

return { env = env }
