# Movetool

Movetool is a tool that allows diassembling binary Move files and reassembling them back into the binary format. As well, it includes a feature to run the verifier.

### Example usage

```
./movetool dis < binary.mv > assembly.mvasm
./movetool asm < assembly.mvasm > new_binary.mv
./movetool verify < new_binary.mv
```

For more details on how to use this tool, as well as an explanation of the Move binary format, see our [blog](https://www.zellic.io/blog/introducing-movetool) about it.
