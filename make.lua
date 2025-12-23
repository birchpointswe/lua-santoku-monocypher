local env = {
  name = "santoku-monocypher",
  version = "0.0.9-1",
  license = "MIT",
  public = true,
  cflags = {
    "-I$(shell luarocks show santoku --rock-dir)/include/",
    "-I$(CURDIR)/../deps/monocypher"
  },
  ldflags = {
    "$(CURDIR)/../deps/monocypher/monocypher.o",
    "$(CURDIR)/../deps/monocypher/sha256.o"
  },
  dependencies = {
    "lua == 5.1",
    "santoku >= 0.0.314-1"
  },
}

env.homepage = "https://github.com/treadwelllane/lua-" .. env.name
env.tarball = env.name .. "-" .. env.version .. ".tar.gz"
env.download = env.homepage .. "/releases/download/" .. env.version .. "/" .. env.tarball

return { env = env }
