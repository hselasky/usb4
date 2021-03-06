//===-- AMDGPUPromoteKernelArguments.cpp ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
/// \file This pass recursively promotes generic pointer arguments of a kernel
/// into the global address space.
///
/// The pass walks kernel's pointer arguments, then loads from them. If a loaded
/// value is a pointer and loaded pointer is unmodified in the kernel before the
/// load, then promote loaded pointer to global. Then recursively continue.
//
//===----------------------------------------------------------------------===//

#include "AMDGPU.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/InitializePasses.h"

#define DEBUG_TYPE "amdgpu-promote-kernel-arguments"

using namespace llvm;

namespace {

class AMDGPUPromoteKernelArguments : public FunctionPass {
  MemorySSA *MSSA;

  Instruction *ArgCastInsertPt;

  SmallVector<Value *> Ptrs;

  void enqueueUsers(Value *Ptr);

  bool promotePointer(Value *Ptr);

public:
  static char ID;

  AMDGPUPromoteKernelArguments() : FunctionPass(ID) {}

  bool run(Function &F, MemorySSA &MSSA);

  bool runOnFunction(Function &F) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<MemorySSAWrapperPass>();
    AU.setPreservesAll();
  }
};

} // end anonymous namespace

void AMDGPUPromoteKernelArguments::enqueueUsers(Value *Ptr) {
  SmallVector<User *> PtrUsers(Ptr->users());

  while (!PtrUsers.empty()) {
    Instruction *U = dyn_cast<Instruction>(PtrUsers.pop_back_val());
    if (!U)
      continue;

    switch (U->getOpcode()) {
    default:
      break;
    case Instruction::Load: {
      LoadInst *LD = cast<LoadInst>(U);
      PointerType *PT = dyn_cast<PointerType>(LD->getType());
      if (!PT ||
          (PT->getAddressSpace() != AMDGPUAS::FLAT_ADDRESS &&
           PT->getAddressSpace() != AMDGPUAS::GLOBAL_ADDRESS &&
           PT->getAddressSpace() != AMDGPUAS::CONSTANT_ADDRESS) ||
          LD->getPointerOperand()->stripInBoundsOffsets() != Ptr)
        break;
      const MemoryAccess *MA = MSSA->getWalker()->getClobberingMemoryAccess(LD);
      // TODO: This load poprobably can be promoted to constant address space.
      if (MSSA->isLiveOnEntryDef(MA))
        Ptrs.push_back(LD);
      break;
    }
    case Instruction::GetElementPtr:
    case Instruction::AddrSpaceCast:
    case Instruction::BitCast:
      if (U->getOperand(0)->stripInBoundsOffsets() == Ptr)
        PtrUsers.append(U->user_begin(), U->user_end());
      break;
    }
  }
}

bool AMDGPUPromoteKernelArguments::promotePointer(Value *Ptr) {
  enqueueUsers(Ptr);

  PointerType *PT = cast<PointerType>(Ptr->getType());
  if (PT->getAddressSpace() != AMDGPUAS::FLAT_ADDRESS)
    return false;

  bool IsArg = isa<Argument>(Ptr);
  IRBuilder<> B(IsArg ? ArgCastInsertPt
                      : &*std::next(cast<Instruction>(Ptr)->getIterator()));

  // Cast pointer to global address space and back to flat and let
  // Infer Address Spaces pass to do all necessary rewriting.
  PointerType *NewPT =
      PointerType::getWithSamePointeeType(PT, AMDGPUAS::GLOBAL_ADDRESS);
  Value *Cast =
      B.CreateAddrSpaceCast(Ptr, NewPT, Twine(Ptr->getName(), ".global"));
  Value *CastBack =
      B.CreateAddrSpaceCast(Cast, PT, Twine(Ptr->getName(), ".flat"));
  Ptr->replaceUsesWithIf(CastBack,
                         [Cast](Use &U) { return U.getUser() != Cast; });

  return true;
}

// skip allocas
static BasicBlock::iterator getInsertPt(BasicBlock &BB) {
  BasicBlock::iterator InsPt = BB.getFirstInsertionPt();
  for (BasicBlock::iterator E = BB.end(); InsPt != E; ++InsPt) {
    AllocaInst *AI = dyn_cast<AllocaInst>(&*InsPt);

    // If this is a dynamic alloca, the value may depend on the loaded kernargs,
    // so loads will need to be inserted before it.
    if (!AI || !AI->isStaticAlloca())
      break;
  }

  return InsPt;
}

bool AMDGPUPromoteKernelArguments::run(Function &F, MemorySSA &MSSA) {
  if (skipFunction(F))
    return false;

  CallingConv::ID CC = F.getCallingConv();
  if (CC != CallingConv::AMDGPU_KERNEL || F.arg_empty())
    return false;

  ArgCastInsertPt = &*getInsertPt(*F.begin());
  this->MSSA = &MSSA;

  for (Argument &Arg : F.args()) {
    if (Arg.use_empty())
      continue;

    PointerType *PT = dyn_cast<PointerType>(Arg.getType());
    if (!PT || (PT->getAddressSpace() != AMDGPUAS::FLAT_ADDRESS &&
                PT->getAddressSpace() != AMDGPUAS::GLOBAL_ADDRESS &&
                PT->getAddressSpace() != AMDGPUAS::CONSTANT_ADDRESS))
      continue;

    Ptrs.push_back(&Arg);
  }

  bool Changed = false;
  while (!Ptrs.empty()) {
    Value *Ptr = Ptrs.pop_back_val();
    Changed |= promotePointer(Ptr);
  }

  return Changed;
}

bool AMDGPUPromoteKernelArguments::runOnFunction(Function &F) {
  MemorySSA &MSSA = getAnalysis<MemorySSAWrapperPass>().getMSSA();
  return run(F, MSSA);
}

INITIALIZE_PASS_BEGIN(AMDGPUPromoteKernelArguments, DEBUG_TYPE,
                      "AMDGPU Promote Kernel Arguments", false, false)
INITIALIZE_PASS_DEPENDENCY(MemorySSAWrapperPass)
INITIALIZE_PASS_END(AMDGPUPromoteKernelArguments, DEBUG_TYPE,
                    "AMDGPU Promote Kernel Arguments", false, false)

char AMDGPUPromoteKernelArguments::ID = 0;

FunctionPass *llvm::createAMDGPUPromoteKernelArgumentsPass() {
  return new AMDGPUPromoteKernelArguments();
}

PreservedAnalyses
AMDGPUPromoteKernelArgumentsPass::run(Function &F,
                                      FunctionAnalysisManager &AM) {
  MemorySSA &MSSA = AM.getResult<MemorySSAAnalysis>(F).getMSSA();
  if (AMDGPUPromoteKernelArguments().run(F, MSSA)) {
    PreservedAnalyses PA;
    PA.preserveSet<CFGAnalyses>();
    PA.preserve<MemorySSAAnalysis>();
    return PA;
  }
  return PreservedAnalyses::all();
}
